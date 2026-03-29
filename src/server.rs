use bytes::{Buf, BytesMut};
use quiche::h3::NameValue;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};

use crate::config::QuicConfig;
use crate::connection::{QuicConnection, StreamMeta, StreamType};
use crate::error::Result;
use crate::realtime::{RealtimeChannel, RealtimeEvent, parse_realtime_frame};

pub type RequestHandler = Arc<
    dyn Fn(
            H3Request,
            Arc<QuicConnection>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = H3Response> + Send>>
        + Send
        + Sync,
>;

pub type RealtimeHandler = Arc<
    dyn Fn(
            RealtimeEvent,
            Arc<RealtimeChannel>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

#[derive(Debug, Clone)]
pub struct H3Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub stream_id: u64,
    pub conn_id: String,
}

#[derive(Debug, Clone)]
pub struct H3Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl H3Response {
    pub fn json(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("content-length".to_string(), body.len().to_string()),
            ],
            body: body,
        }
    }
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        let body = body.into();
        Self {
            status: 200,
            headers: vec![("content-length".to_string(), body.len().to_string())],
            body,
        }
    }
    pub fn not_found() -> Self {
        Self::json(404, Vec::new())
    }
}

pub struct H3Server {
    bind_addr: SocketAddr,
    config: QuicConfig,
    request_handler: Option<RequestHandler>,
    realtime_handler: Option<RealtimeHandler>,
    pub channel: RealtimeChannel,
}

struct PendingResponse {
    conn: Arc<QuicConnection>,
    stream_id: u64,
    response: H3Response,
}

impl H3Server {
    pub fn new(bind_addr: SocketAddr, config: QuicConfig) -> Self {
        Self {
            bind_addr,
            config,
            request_handler: None,
            realtime_handler: None,
            channel: RealtimeChannel::new(),
        }
    }

    pub fn on_request<F, Fut>(mut self, handler: F) -> Self
    where
        F: Fn(H3Request, Arc<QuicConnection>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = H3Response> + Send + 'static,
    {
        self.request_handler = Some(Arc::new(move |req, conn| Box::pin(handler(req, conn))));
        self
    }

    pub fn on_realtime<F, Fut>(mut self, handler: F) -> Self
    where
        F: Fn(RealtimeEvent, Arc<RealtimeChannel>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.realtime_handler = Some(Arc::new(move |ev, ch| Box::pin(handler(ev, ch))));
        self
    }

    pub async fn run(self) -> Result<()> {
        let socket = Arc::new(UdpSocket::bind(self.bind_addr).await?);
        info!("HTTP/3 server listening on {}", self.bind_addr);

        let mut quiche_config = self.config.build_quiche_config()?;
        let channel = Arc::new(self.channel.clone_handle());
        let req_handler = self.request_handler.clone();
        let rt_handler = self.realtime_handler.clone();

        let connections: Arc<RwLock<HashMap<String, Arc<QuicConnection>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let cid_map: Arc<RwLock<HashMap<Vec<u8>, String>>> = Arc::new(RwLock::new(HashMap::new()));

        let (resp_tx, mut resp_rx) = mpsc::channel::<PendingResponse>(256);

        let mut buf = BytesMut::zeroed(65535);
        let mut out = BytesMut::zeroed(1350);

        loop {
            enum Event {
                Packet { len: usize, from: SocketAddr },
                Response(PendingResponse),
            }

            let event = tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) => Event::Packet { len, from: addr },
                        Err(e) => { error!("recv_from: {e}"); continue; }
                    }
                },
                Some(pending) = resp_rx.recv() => {
                    Event::Response(pending)
                },
            };

            match event {
                Event::Response(pending) => {
                    let PendingResponse {
                        conn,
                        stream_id,
                        response,
                    } = pending;

                    let status_str = response.status.to_string();
                    let mut h3_headers = vec![
                        quiche::h3::Header::new(b":status", status_str.as_bytes()),
                        quiche::h3::Header::new(b"server", b"quic-h3/0.1"),
                    ];
                    for (k, v) in &response.headers {
                        h3_headers.push(quiche::h3::Header::new(k.as_bytes(), v.as_bytes()));
                    }

                    if let Err(e) = conn
                        .send_h3_response(stream_id, &h3_headers, Some(&response.body))
                        .await
                    {
                        error!("send_h3_response stream {stream_id}: {e}");
                        continue;
                    }

                    let peer = conn.peer_addr;
                    let mut quic = conn.quic.lock().await;
                    loop {
                        let (write, _) = match quic.send(&mut out) {
                            Ok(v) => v,
                            Err(quiche::Error::Done) => break,
                            Err(e) => {
                                error!("quic.send (resp): {e}");
                                break;
                            }
                        };
                        if let Err(e) = socket.send_to(&out[..write], peer).await {
                            error!("send_to (resp): {e}");
                        }
                    }
                    debug!("Flushed response for stream {stream_id} to {peer}");
                    continue;
                }

                Event::Packet {
                    len,
                    from: pkt_from,
                } => {
                    let pkt = &mut buf[..len];

                    let hdr = match quiche::Header::from_slice(pkt, quiche::MAX_CONN_ID_LEN) {
                        Ok(h) => h,
                        Err(e) => {
                            warn!("Bad QUIC header from {pkt_from}: {e}");
                            continue;
                        }
                    };

                    let dcid_bytes: Vec<u8> = hdr.dcid.as_ref().to_vec();

                    let conn_arc: Option<Arc<QuicConnection>> = {
                        let cids = cid_map.read().await;
                        if let Some(uuid) = cids.get(&dcid_bytes) {
                            connections.read().await.get(uuid).cloned()
                        } else {
                            None
                        }
                    };

                    let conn_arc: Arc<QuicConnection> = if let Some(c) = conn_arc {
                        c
                    } else if hdr.ty != quiche::Type::Initial {
                        let fallback = {
                            let conns = connections.read().await;
                            conns
                                .values()
                                .find(|c| {
                                    if c.peer_addr != pkt_from {
                                        return false;
                                    }
                                    c.quic.try_lock().map(|q| !q.is_closed()).unwrap_or(true)
                                })
                                .cloned()
                        };
                        if let Some(c) = fallback {
                            cid_map
                                .write()
                                .await
                                .insert(dcid_bytes.clone(), c.conn_id.clone());
                            debug!(
                                "Short dcid=0x{} resolved via peer {} → {}",
                                hex::encode(&dcid_bytes),
                                pkt_from,
                                c.conn_id
                            );
                            c
                        } else {
                            warn!(
                                "Non-initial ({:?}) from {pkt_from}, dcid=0x{} — drop",
                                hdr.ty,
                                hex::encode(&dcid_bytes)
                            );
                            continue;
                        }
                    } else {
                        {
                            let old = {
                                let conns = connections.read().await;
                                conns
                                    .values()
                                    .find(|c| c.peer_addr == pkt_from)
                                    .map(|c| (c.conn_id.clone(), Arc::clone(c)))
                            };
                            if let Some((old_uuid, old_conn)) = old {
                                info!(
                                    "Retiring old connection {old_uuid} for peer {pkt_from} (client reconnect)"
                                );
                                if let Ok(mut quic) = old_conn.quic.try_lock() {
                                    let _ = quic.close(false, 0, b"superseded");
                                }
                                connections.write().await.remove(&old_uuid);
                                cid_map.write().await.retain(|_, v| v != &old_uuid);
                            }
                        }

                        let scid = quiche::ConnectionId::from_ref(&hdr.dcid);
                        let internal_id = QuicConnection::generate_conn_id();
                        let (rt_tx, mut rt_rx) = mpsc::channel::<RealtimeEvent>(256);

                        let quic_conn = match quiche::accept(
                            &scid,
                            None,
                            self.bind_addr,
                            pkt_from,
                            &mut quiche_config,
                        ) {
                            Ok(c) => c,
                            Err(e) => {
                                error!("quiche::accept: {e}");
                                continue;
                            }
                        };

                        let conn = Arc::new(QuicConnection::new(
                            internal_id.clone(),
                            pkt_from,
                            quic_conn,
                            rt_tx,
                        ));
                        cid_map
                            .write()
                            .await
                            .insert(dcid_bytes.clone(), internal_id.clone());
                        connections
                            .write()
                            .await
                            .insert(internal_id.clone(), conn.clone());

                        {
                            let ch = Arc::clone(&channel);
                            let rt_h = rt_handler.clone();
                            tokio::spawn(async move {
                                while let Some(ev) = rt_rx.recv().await {
                                    if let Some(h) = &rt_h {
                                        h(ev, Arc::clone(&ch)).await;
                                    }
                                }
                            });
                        }

                        info!("New connection from {pkt_from} → {internal_id}");
                        conn
                    };

                    {
                        let recv_info = quiche::RecvInfo {
                            to: self.bind_addr,
                            from: pkt_from,
                        };
                        let mut quic = conn_arc.quic.lock().await;
                        if let Err(e) = quic.recv(pkt, recv_info) {
                            warn!("quic.recv {}: {e}", conn_arc.conn_id);
                        }
                    }

                    if conn_arc.is_established().await && conn_arc.h3.lock().await.is_none() {
                        if let Err(e) = conn_arc.init_h3_server().await {
                            error!("H3 init {}: {e}", conn_arc.conn_id);
                        } else {
                            info!("H3 ready for {}", conn_arc.conn_id);
                        }
                    }

                    if conn_arc.h3.lock().await.is_some() {
                        Self::process_h3_events(&conn_arc, req_handler.as_ref(), &resp_tx).await;
                    }

                    Self::process_realtime_streams(&conn_arc, &channel, &socket).await;
                    Self::process_datagrams(&conn_arc, &channel, &socket).await;

                    {
                        let mut quic = conn_arc.quic.lock().await;
                        loop {
                            let (write, _) = match quic.send(&mut out) {
                                Ok(v) => v,
                                Err(quiche::Error::Done) => break,
                                Err(e) => {
                                    error!("quic.send: {e}");
                                    break;
                                }
                            };
                            if let Err(e) = socket.send_to(&out[..write], pkt_from).await {
                                error!("send_to: {e}");
                            }
                        }
                    }

                    {
                        let quic = conn_arc.quic.lock().await;
                        let uuid = conn_arc.conn_id.clone();
                        let mut cids = cid_map.write().await;
                        for cid in quic.source_ids() {
                            let key = cid.as_ref().to_vec();
                            cids.entry(key).or_insert_with(|| {
                                debug!("+ source CID 0x{} → {uuid}", hex::encode(cid.as_ref()));
                                uuid.clone()
                            });
                        }
                        {
                            let key = quic.destination_id().as_ref().to_vec();
                            cids.entry(key).or_insert_with(|| {
                                debug!(
                                    "+ dest   CID 0x{} → {uuid}",
                                    hex::encode(quic.destination_id().as_ref())
                                );
                                uuid.clone()
                            });
                        }
                    }

                    if conn_arc.is_closed().await {
                        let uuid = &conn_arc.conn_id;

                        let _ = conn_arc
                            .realtime_tx
                            .send(RealtimeEvent::Disconnected {
                                conn_id: uuid.clone(),
                            })
                            .await;

                        connections.write().await.remove(uuid);
                        cid_map.write().await.retain(|_, v| v != uuid);
                        info!("Connection {uuid} removed");
                    }
                }
            }
        }
    }

    pub async fn process_datagrams(
        conn: &Arc<QuicConnection>,
        channel: &Arc<RealtimeChannel>,
        socket: &Arc<UdpSocket>,
    ) {
        let mut buf = BytesMut::zeroed(65535);

        let mut quic = conn.quic.lock().await;

        while let Ok(len) = quic.dgram_recv(&mut buf) {
            let raw_data = &buf[..len];

            if let Some((session_id, varint_len)) = crate::realtime::decode_quic_varint(raw_data) {
                let actual_json_data = &raw_data[varint_len..];
                debug!("receive datagram {} bytes from conn {}", len, session_id);

                if let Some((msg, _)) = parse_realtime_frame(actual_json_data) {
                    if msg.event == "join" {
                        let mut rx = channel.subscribe(&msg.channel, &conn.conn_id).await;
                        let conn_c = Arc::clone(conn);
                        let sid = session_id;
                        let socket_c = Arc::clone(socket);
                        let peer_addr = conn_c.peer_addr;

                        tokio::spawn(async move {
                            while let Some(shared_frame) = rx.recv().await {
                                let varint = crate::realtime::encode_quic_varint(sid);

                                let mut final_payload =
                                    Vec::with_capacity(varint.len() + shared_frame.len());
                                final_payload.extend_from_slice(&varint);
                                final_payload.extend_from_slice(&shared_frame);

                                let mut quic = conn_c.quic.lock().await;
                                if let Err(e) = quic.dgram_send(&final_payload) {
                                    tracing::warn!(
                                        "Gagal kirim broadcast datagram ke client: {}",
                                        e
                                    );
                                }
                                drop(quic);

                                let mut out = BytesMut::zeroed(1350);
                                loop {
                                    let write = {
                                        let mut q = conn_c.quic.lock().await;
                                        match q.send(&mut out) {
                                            Ok((w, _)) => w,
                                            Err(_) => break,
                                        }
                                    };
                                    let _ = socket_c.send_to(&out[..write], peer_addr).await;
                                }
                            }
                        });

                        let _ = conn
                            .realtime_tx
                            .send(RealtimeEvent::Join {
                                conn_id: conn.conn_id.clone(),
                                channel: msg.channel.clone(),
                                stream_id: session_id,
                            })
                            .await;
                    } else if msg.event == "leave" {
                        channel.unsubscribe(&msg.channel, &conn.conn_id).await;

                        let _ = conn
                            .realtime_tx
                            .send(RealtimeEvent::Leave {
                                conn_id: conn.conn_id.clone(),
                                channel: msg.channel.clone(),
                            })
                            .await;
                    } else {
                        let _ = conn
                            .realtime_tx
                            .send(RealtimeEvent::Message {
                                conn_id: conn.conn_id.clone(),
                                stream_id: session_id,
                                msg,
                            })
                            .await;
                    }
                }
            }
        }
    }

    async fn process_h3_events(
        conn: &Arc<QuicConnection>,
        handler: Option<&RequestHandler>,
        resp_tx: &mpsc::Sender<PendingResponse>,
    ) {
        let mut pending: HashMap<u64, H3Request> = HashMap::new();

        loop {
            let event = {
                let mut quic = conn.quic.lock().await;
                let mut h3g = conn.h3.lock().await;
                let h3 = match h3g.as_mut() {
                    Some(h) => h,
                    None => break,
                };
                match h3.poll(&mut quic) {
                    Ok(ev) => ev,
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => {
                        warn!(
                            "[process_h3_events] H3 poll error on connection {}: {:?}",
                            conn.conn_id, e
                        );
                        break;
                    }
                }
            };

            match event {
                (stream_id, quiche::h3::Event::Headers { list, .. }) => {
                    let mut method = String::new();
                    let mut path = String::new();
                    let mut headers = Vec::new();
                    let mut protocol = String::new();

                    for hdr in &list {
                        let k = std::str::from_utf8(hdr.name()).unwrap_or("").to_string();
                        let v = std::str::from_utf8(hdr.value()).unwrap_or("").to_string();
                        match k.as_str() {
                            ":method" => method = v,
                            ":path" => path = v,
                            ":protocol" => protocol = v,
                            _ => headers.push((k, v)),
                        }
                    }
                    if method == "CONNECT" && protocol == "webtransport" {
                        debug!("Receiving request webtransport on stream_id={}", stream_id);
                        let rep_headers = vec![
                            quiche::h3::Header::new(b":status", b"200"),
                            quiche::h3::Header::new(b"sec-webtransport-http3-draft", b"draft02"),
                        ];

                        let mut quic = conn.quic.lock().await;
                        let mut h3g = conn.h3.lock().await;

                        if let Some(h3) = h3g.as_mut() {
                            if let Ok(_) =
                                h3.send_response(&mut *quic, stream_id, &rep_headers, false)
                            {
                                info!("web transport session established: {}", stream_id);
                                let mut streams = conn.streams.lock().await;
                                streams.insert(
                                    stream_id,
                                    StreamMeta {
                                        stream_id,
                                        stream_type: StreamType::Realtime,
                                        channel: None,
                                        buffer: BytesMut::with_capacity(8192),
                                    },
                                );
                            }
                        }

                        continue;
                    }

                    info!("H3 {method} {path} stream={stream_id}");
                    pending.insert(
                        stream_id,
                        H3Request {
                            method,
                            path,
                            headers,
                            body: vec![],
                            stream_id,
                            conn_id: conn.conn_id.clone(),
                        },
                    );
                }

                (stream_id, quiche::h3::Event::Data) => {
                    let mut quic = conn.quic.lock().await;
                    let mut h3g = conn.h3.lock().await;
                    let mut streams = conn.streams.lock().await;

                    if let Some(h3) = h3g.as_mut() {
                        let mut body_buf = bytes::BytesMut::zeroed(65535);

                        while let Ok(read) = h3.recv_body(&mut *quic, stream_id, &mut body_buf) {
                            if let Some(req) = pending.get_mut(&stream_id) {
                                req.body.extend_from_slice(&body_buf[..read]);
                            } else if let Some(meta) = streams.get_mut(&stream_id) {
                                meta.buffer.extend_from_slice(&body_buf[..read]);
                            }
                        }
                    }
                }

                (stream_id, quiche::h3::Event::Finished) => {
                    if let Some(req) = pending.remove(&stream_id) {
                        if let Some(h) = handler {
                            let conn_c = Arc::clone(conn);
                            let h_c = Arc::clone(h);
                            let resp_tx_c = resp_tx.clone();
                            tokio::spawn(async move {
                                let response = h_c(req, Arc::clone(&conn_c)).await;
                                if let Err(e) = resp_tx_c
                                    .send(PendingResponse {
                                        conn: conn_c,
                                        stream_id,
                                        response,
                                    })
                                    .await
                                {
                                    error!("Failed to send pending response: {e}");
                                }
                            });
                        }
                    }
                }

                _ => {}
            }
        }
    }

    async fn process_realtime_streams(
        conn: &Arc<QuicConnection>,
        channel: &Arc<RealtimeChannel>,
        socket: &Arc<UdpSocket>,
    ) {
        let mut streams = conn.streams.lock().await;

        for (&stream_id, meta) in streams.iter_mut() {
            if meta.stream_type != StreamType::Realtime {
                continue;
            }

            while let Some((msg, consumed)) = parse_realtime_frame(&meta.buffer) {
                use bytes::Buf;
                meta.buffer.advance(consumed);

                if msg.event == "join" {
                    let ch_name = msg.channel.clone();
                    meta.channel = Some(ch_name.clone());

                    let mut rx = channel.subscribe(&ch_name, &conn.conn_id).await;
                    let conn_c = Arc::clone(conn);
                    let socket_c = Arc::clone(socket);
                    let peer_addr = conn.peer_addr;

                    tokio::spawn(async move {
                        while let Some(bcast) = rx.recv().await {
                            let mut quic = conn_c.quic.lock().await;
                            let mut h3g = conn_c.h3.lock().await;

                            if let Some(h3) = h3g.as_mut() {
                                if let Err(e) = h3.send_body(&mut *quic, stream_id, &bcast, false) {
                                    if !matches!(e, quiche::h3::Error::Done) {
                                        break;
                                    }
                                }
                            }

                            let mut out = bytes::BytesMut::zeroed(1350);
                            loop {
                                match quic.send(&mut out) {
                                    Ok((w, _)) => {
                                        let _ = socket_c.send_to(&out[..w], peer_addr).await;
                                    }
                                    _ => break,
                                }
                            }
                        }
                    });
                    let _ = conn
                        .realtime_tx
                        .send(RealtimeEvent::Join {
                            conn_id: conn.conn_id.clone(),
                            channel: ch_name,
                            stream_id,
                        })
                        .await;
                } else if msg.event == "leave" {
                    if let Some(ch) = &meta.channel {
                        channel.unsubscribe(ch, &conn.conn_id).await;

                        let _ = conn
                            .realtime_tx
                            .send(RealtimeEvent::Leave {
                                conn_id: conn.conn_id.clone(),
                                channel: ch.clone(),
                            })
                            .await;
                    }
                } else {
                    let _ = conn
                        .realtime_tx
                        .send(RealtimeEvent::Message {
                            conn_id: conn.conn_id.clone(),
                            stream_id,
                            msg,
                        })
                        .await;
                }
            }
        }
    }
}
