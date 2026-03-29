use bytes::BytesMut;
use quiche::h3::NameValue;
use ring::rand::SecureRandom;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info, warn};

use crate::config::QuicConfig;
use crate::connection::QuicConnection;
use crate::error::{H3Error, Result};
use crate::realtime::{RealtimeEvent, RealtimeMessage, RealtimeMode, parse_realtime_frame};

pub struct H3Client {
    server_addr: SocketAddr,
    local_addr: SocketAddr,
    config: QuicConfig,
    server_name: String,
}

#[derive(Debug)]
pub struct H3ClientResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub struct RealtimeStreamHandle {
    pub stream_id: u64,
    conn: Arc<QuicConnection>,
    pub rx: mpsc::Receiver<RealtimeMessage>,
    pub channel: String,
    pub socket: Arc<UdpSocket>,
    pub mode: RealtimeMode,
}

impl RealtimeStreamHandle {
    pub async fn send(&self, event: &str, payload: Vec<u8>) -> Result<()> {
        let msg = RealtimeMessage::new(event, &self.channel, payload);
        let json_frame = crate::realtime::encode_realtime_frame(&msg)?;

        if self.mode == RealtimeMode::Unrealible {
            let mut final_payload = crate::realtime::encode_quic_varint(self.stream_id);
            final_payload.extend_from_slice(&json_frame);

            {
                let mut quic = self.conn.quic.lock().await;
                if let Err(e) = quic.dgram_send(&final_payload) {
                    tracing::warn!("failed send datagram: {}", e);
                }
            }
        } else {
            {
                let mut quic = self.conn.quic.lock().await;
                let mut h3g = self.conn.h3.lock().await;
                if let Some(h3) = h3g.as_mut() {
                    h3.send_body(&mut *quic, self.stream_id, &json_frame, false)?;
                }
            }
        }

        let mut out = BytesMut::zeroed(1350);
        loop {
            let write = {
                let mut quic = self.conn.quic.lock().await;
                match quic.send(&mut out) {
                    Ok((w, _)) => w,
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        return Err(crate::error::H3Error::InvalidFrame(e.to_string()));
                    }
                }
            };
            let _ = self.socket.send(&out[..write]).await;
        }
        Ok(())
    }

    pub async fn recv(&mut self) -> Option<RealtimeMessage> {
        self.rx.recv().await
    }

    pub fn split(
        self,
    ) -> (
        std::sync::Arc<Self>,
        tokio::sync::mpsc::Receiver<crate::realtime::RealtimeMessage>,
    ) {
        let rx = self.rx;

        let (_dummy_tx, dummy_rx) = tokio::sync::mpsc::channel(1);
        let sender_only = Self {
            stream_id: self.stream_id,
            conn: self.conn,
            rx: dummy_rx,
            channel: self.channel,
            socket: self.socket,
            mode: self.mode,
        };

        (std::sync::Arc::new(sender_only), rx)
    }
}

impl H3Client {
    pub fn new(
        server_addr: SocketAddr,
        local_addr: SocketAddr,
        config: QuicConfig,
        server_name: impl Into<String>,
    ) -> Self {
        Self {
            server_addr,
            local_addr,
            config,
            server_name: server_name.into(),
        }
    }

    pub async fn connect(self) -> Result<H3ClientConn> {
        let socket = Arc::new(UdpSocket::bind(self.local_addr).await?);
        socket.connect(self.server_addr).await?;

        let actual_local = socket.local_addr()?;

        let mut quiche_config = self.config.build_quiche_config()?;

        let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut scid_bytes)
            .map_err(|_| H3Error::InvalidFrame("rng failed".into()))?;
        let scid = quiche::ConnectionId::from_ref(&scid_bytes);

        let quic_conn = quiche::connect(
            Some(&self.server_name),
            &scid,
            actual_local,
            self.server_addr,
            &mut quiche_config,
        )?;

        let (rt_tx, rt_rx) = mpsc::channel(256);
        let conn = Arc::new(QuicConnection::new(
            QuicConnection::generate_conn_id(),
            self.server_addr,
            quic_conn,
            rt_tx,
        ));

        info!(
            "Connecting to {} (local {}) ...",
            self.server_addr, actual_local
        );

        Ok(H3ClientConn {
            socket,
            conn,
            local_addr: actual_local,
            server_addr: self.server_addr,
            rt_rx,
            closed: Arc::new(Mutex::new(false)),
        })
    }
}

pub struct H3ClientConn {
    socket: Arc<UdpSocket>,
    pub conn: Arc<QuicConnection>,
    local_addr: SocketAddr,
    server_addr: SocketAddr,
    rt_rx: mpsc::Receiver<RealtimeEvent>,
    closed: Arc<Mutex<bool>>,
}

impl H3ClientConn {
    pub async fn handshake(&self) -> Result<()> {
        let mut out = BytesMut::zeroed(1350);
        let mut buf = BytesMut::zeroed(65535);
        let timeout = std::time::Duration::from_secs(10);
        let start = Instant::now();

        loop {
            if start.elapsed() > timeout {
                return Err(H3Error::HandshakeTimeout);
            }

            self.flush_raw(&mut out).await?;

            if self.conn.is_established().await {
                break;
            }

            let recv_timeout = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                self.socket.recv(&mut buf),
            );

            match recv_timeout.await {
                Ok(Ok(len)) => {
                    let recv_info = quiche::RecvInfo {
                        to: self.local_addr,
                        from: self.server_addr,
                    };
                    let mut quic = self.conn.quic.lock().await;
                    if let Err(e) = quic.recv(&mut buf[..len], recv_info) {
                        warn!("handshake recv: {e}");
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {}
            }
        }

        self.conn.init_h3_client().await?;
        info!("Connected and H3 initialized!");
        Ok(())
    }

    pub async fn get(&self, path: &str) -> Result<H3ClientResponse> {
        self.request("GET", path, &[], None).await
    }

    pub async fn post_json(&self, path: &str, body: Option<&[u8]>) -> Result<H3ClientResponse> {
        self.request("POST", path, &[("content-type", "application/json")], body)
            .await
    }

    pub async fn request(
        &self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<H3ClientResponse> {
        if self.conn.is_closed().await {
            return Err(H3Error::ConnectionClosed);
        }

        let mut headers = vec![
            quiche::h3::Header::new(b":method", method.as_bytes()),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":path", path.as_bytes()),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b"user-agent", b"quic-h3/0.1"),
        ];
        for (k, v) in extra_headers {
            headers.push(quiche::h3::Header::new(k.as_bytes(), v.as_bytes()));
        }

        let stream_id = {
            let mut quic = self.conn.quic.lock().await;
            let mut h3g = self.conn.h3.lock().await;
            let h3 = h3g.as_mut().ok_or(H3Error::ConnectionClosed)?;
            h3.send_request(&mut *quic, &headers, body.is_none())?
        };

        if let Some(data) = body {
            let mut quic = self.conn.quic.lock().await;
            let mut h3g = self.conn.h3.lock().await;
            let h3 = h3g.as_mut().ok_or(H3Error::ConnectionClosed)?;
            h3.send_body(&mut *quic, stream_id, data, true)?;
        }

        self.flush().await?;

        let mut resp_status = 0u16;
        let mut resp_headers = Vec::new();
        let mut resp_body = Vec::new();
        let mut buf = BytesMut::zeroed(65535);
        let mut out = BytesMut::zeroed(1350);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);

        loop {
            if self.conn.is_closed().await {
                return Err(H3Error::ConnectionClosed);
            }

            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                self.close_internal("request timeout").await;
                return Err(H3Error::HandshakeTimeout);
            }

            match tokio::time::timeout(remaining, self.socket.recv(&mut buf)).await {
                Ok(Ok(len)) => {
                    let recv_info = quiche::RecvInfo {
                        to: self.local_addr,
                        from: self.server_addr,
                    };
                    let mut quic = self.conn.quic.lock().await;
                    if let Err(e) = quic.recv(&mut buf[..len], recv_info) {
                        warn!("quic.recv in request: {e}");
                        if matches!(e, quiche::Error::Done) {
                            continue;
                        }
                        drop(quic);
                        self.close_internal(&format!("recv error: {e}")).await;
                        return Err(e.into());
                    }
                }
                Ok(Err(e)) => {
                    self.close_internal("socket error").await;
                    return Err(e.into());
                }
                Err(_) => {
                    self.close_internal("request timeout").await;
                    return Err(H3Error::HandshakeTimeout);
                }
            }

            if let Err(e) = self.flush_raw(&mut out).await {
                self.close_internal("flush error").await;
                return Err(e);
            }

            loop {
                let event = {
                    let mut quic = self.conn.quic.lock().await;
                    let mut h3g = self.conn.h3.lock().await;
                    let h3 = match h3g.as_mut() {
                        Some(h) => h,
                        None => {
                            return Err(H3Error::ConnectionClosed);
                        }
                    };
                    match h3.poll(&mut *quic) {
                        Ok(ev) => ev,
                        Err(quiche::h3::Error::Done) => break,
                        Err(quiche::h3::Error::TransportError(te)) => {
                            drop(h3g);
                            drop(quic);
                            self.close_internal(&format!("transport error: {te:?}"))
                                .await;
                            return Err(H3Error::ConnectionClosed);
                        }
                        Err(e) => {
                            warn!("H3 poll error: {e}");
                            break;
                        }
                    }
                };

                debug!("rt_rx {:?}", self.rt_rx);
                match event {
                    (sid, quiche::h3::Event::Headers { list, .. }) if sid == stream_id => {
                        for hdr in &list {
                            let k = std::str::from_utf8(hdr.name()).unwrap_or("").to_string();
                            let v = std::str::from_utf8(hdr.value()).unwrap_or("").to_string();
                            if k == ":status" {
                                resp_status = v.parse().unwrap_or(0);
                            } else {
                                resp_headers.push((k, v));
                            }
                        }
                    }

                    (sid, quiche::h3::Event::Data) if sid == stream_id => {
                        let mut body_buf = BytesMut::zeroed(65535);
                        let n = {
                            let mut quic = self.conn.quic.lock().await;
                            let mut h3g = self.conn.h3.lock().await;
                            h3g.as_mut()
                                .map(|h| h.recv_body(&mut *quic, sid, &mut body_buf).unwrap_or(0))
                                .unwrap_or(0)
                        };
                        resp_body.extend_from_slice(&body_buf[..n]);
                    }

                    (sid, quiche::h3::Event::Finished) if sid == stream_id => {
                        debug!("Stream {sid} finished");
                        return Ok(H3ClientResponse {
                            status: resp_status,
                            headers: resp_headers,
                            body: resp_body,
                        });
                    }

                    (sid, quiche::h3::Event::Reset(code)) if sid == stream_id => {
                        warn!("Stream {sid} reset by server, code={code}");
                        return Err(H3Error::InvalidFrame(format!("stream reset: {code}")));
                    }

                    (_, quiche::h3::Event::GoAway) => {
                        warn!("Server sent GOAWAY");
                        if resp_status > 0 {
                            return Ok(H3ClientResponse {
                                status: resp_status,
                                headers: resp_headers,
                                body: resp_body,
                            });
                        }
                        self.close_internal("GOAWAY received").await;
                        return Err(H3Error::ConnectionClosed);
                    }

                    _ => {}
                }
            }
        }
    }

    pub async fn close(&self) {
        self.close_internal("client close").await;
    }

    async fn close_internal(&self, reason: &str) {
        let mut closed = self.closed.lock().await;
        if *closed {
            return;
        }
        *closed = true;
        drop(closed);

        info!("Closing connection: {reason}");

        {
            let mut quic = self.conn.quic.lock().await;
            if !quic.is_closed() {
                let _ = quic.close(false, 0x0, reason.as_bytes());
            }
            let mut out = BytesMut::zeroed(1350);
            for _ in 0..3 {
                match quic.send(&mut out) {
                    Ok((w, _)) => {
                        let _ = self.socket.send(&out[..w]).await;
                    }
                    Err(quiche::Error::Done) => break,
                    Err(_) => break,
                }
            }
        }
    }

    async fn webtransport_connect(&self, path: &str) -> Result<u64> {
        if self.conn.is_closed().await {
            return Err(H3Error::ConnectionClosed);
        }

        let headers = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"webtransport"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", path.as_bytes()),
            quiche::h3::Header::new(b"sec-webtransport-http3-draft", b"draft02"),
        ];

        let stream_id = {
            let mut quic = self.conn.quic.lock().await;
            let mut h3g = self.conn.h3.lock().await;
            let h3 = h3g.as_mut().ok_or(H3Error::ConnectionClosed)?;
            h3.send_request(&mut *quic, &headers, false)?
        };

        self.flush().await?;

        let mut buf = BytesMut::zeroed(65535);
        let mut out = BytesMut::zeroed(1350);

        loop {
            let Ok(len) = self.socket.recv(&mut buf).await else {
                return Err(H3Error::ConnectionClosed);
            };

            let recv_info = quiche::RecvInfo {
                to: self.local_addr,
                from: self.server_addr,
            };

            {
                let mut quic = self.conn.quic.lock().await;
                let _ = quic.recv(&mut buf[..len], recv_info);
            }

            self.flush_raw(&mut out).await?;

            let mut quic = self.conn.quic.lock().await;
            let mut h3g = self.conn.h3.lock().await;
            let h3 = h3g.as_mut().unwrap();

            match h3.poll(&mut *quic) {
                Ok((sid, quiche::h3::Event::Headers { list, .. })) if sid == stream_id => {
                    let mut status = 0;
                    for hdr in &list {
                        if hdr.name() == b":status" {
                            let v = std::str::from_utf8(hdr.value()).unwrap_or("");
                            status = v.parse().unwrap_or(0);
                        }
                    }
                    if status >= 200 && status < 300 {
                        info!(
                            "WebTransport session established! Session ID: {}",
                            stream_id
                        );
                        return Ok(stream_id);
                    } else {
                        return Err(H3Error::InvalidFrame(format!(
                            "WebTransport ditolak: {}",
                            status
                        )));
                    }
                }
                Ok(_) => continue,
                Err(quiche::h3::Error::Done) => continue,
                Err(e) => return Err(H3Error::InvalidFrame(format!("H3 Poll error: {:?}", e))),
            }
        }
    }

    pub async fn realtime_connect(
        &self,
        channel: &str,
        mode: RealtimeMode,
    ) -> Result<RealtimeStreamHandle> {
        let path = format!("/realtime?channel={}", channel);
        let session_id = self.webtransport_connect(&path).await?;

        let join_msg = RealtimeMessage::new("join", channel, vec![]);
        let join_frame = crate::realtime::encode_realtime_frame(&join_msg)?;

        if mode == RealtimeMode::Unrealible {
            let mut final_payload = crate::realtime::encode_quic_varint(session_id);
            final_payload.extend_from_slice(&join_frame);

            {
                let mut quic = self.conn.quic.lock().await;
                let _ = quic.dgram_send(&final_payload);
            }
        } else {
            let mut quic = self.conn.quic.lock().await;
            let mut h3g = self.conn.h3.lock().await;
            if let Some(h3) = h3g.as_mut() {
                h3.send_body(&mut *quic, session_id, &join_frame, false)?;
            }
        }

        self.flush().await?;

        let (tx, rx) = mpsc::channel(256);
        let socket = Arc::clone(&self.socket);
        let conn = Arc::clone(&self.conn);
        let local_addr = self.local_addr;
        let server_addr = self.server_addr;

        tokio::spawn(async move {
            let mut recv_buf = BytesMut::zeroed(65535);
            let mut out = BytesMut::zeroed(1350);
            let mut reliable_buffer = bytes::BytesMut::with_capacity(65535);

            loop {
                let Ok(len) = socket.recv(&mut recv_buf).await else {
                    break;
                };

                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from: server_addr,
                };

                {
                    let mut quic = conn.quic.lock().await;
                    if let Err(e) = quic.recv(&mut recv_buf[..len], recv_info) {
                        warn!("realtime recv: {e}");
                    }
                }

                {
                    let mut quic = conn.quic.lock().await;
                    loop {
                        match quic.send(&mut out) {
                            Ok((w, _)) => {
                                let _ = socket.send(&out[..w]).await;
                            }
                            Err(quiche::Error::Done) | Err(_) => break,
                        }
                    }
                }

                let mut quic = conn.quic.lock().await;
                if mode == RealtimeMode::Unrealible {
                    let mut dgram_buf = BytesMut::zeroed(65535);
                    while let Ok(d_len) = quic.dgram_recv(&mut dgram_buf) {
                        let raw_data = &dgram_buf[..d_len];
                        if let Some((_sid, varint_len)) =
                            crate::realtime::decode_quic_varint(raw_data)
                        {
                            let actual_json = &raw_data[varint_len..];
                            if let Some((msg, _)) = parse_realtime_frame(actual_json) {
                                if tx.send(msg).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                } else {
                    let mut h3g = conn.h3.lock().await;
                    if let Some(h3) = h3g.as_mut() {
                        loop {
                            match h3.poll(&mut *quic) {
                                Ok((sid, quiche::h3::Event::Data)) if sid == session_id => {
                                    let mut body_buf = bytes::BytesMut::zeroed(65535);

                                    while let Ok(read) =
                                        h3.recv_body(&mut *quic, sid, &mut body_buf)
                                    {
                                        info!("got bytes {} on stream {}", read, sid);
                                        reliable_buffer.extend_from_slice(&body_buf[..read]);

                                        while let Some((msg, consumed)) =
                                            parse_realtime_frame(&reliable_buffer)
                                        {
                                            use bytes::Buf;
                                            reliable_buffer.advance(consumed);
                                            if tx.send(msg).await.is_err() {
                                                return;
                                            }
                                        }
                                    }
                                }
                                Ok((sid, quiche::h3::Event::Finished)) if sid == session_id => {
                                    info!("reliable stream {} closed by server", sid);
                                    return;
                                }
                                Ok(_) => continue,
                                Err(quiche::h3::Error::Done) => break,
                                Err(e) => {
                                    warn!("H3 poll error di client: {:?}", e);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });
        Ok(RealtimeStreamHandle {
            stream_id: session_id,
            conn: Arc::clone(&self.conn),
            rx,
            channel: String::from(channel),
            socket: Arc::clone(&self.socket),
            mode: mode,
        })
    }

    async fn flush_raw(&self, out: &mut [u8]) -> Result<()> {
        loop {
            let write = {
                let mut quic = self.conn.quic.lock().await;
                match quic.send(out) {
                    Ok((w, _)) => w,
                    Err(quiche::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
            };

            self.socket.send(&out[..write]).await?;
        }
        Ok(())
    }

    pub async fn flush(&self) -> Result<()> {
        let mut out = BytesMut::zeroed(1350);
        self.flush_raw(&mut out).await
    }
}

impl Drop for H3ClientConn {
    fn drop(&mut self) {
        let closed = Arc::clone(&self.closed);
        // let socket = Arc::clone(&self.socket);
        let conn = Arc::clone(&self.conn);

        if let Ok(mut flag) = closed.try_lock() {
            if !*flag {
                *flag = true;
                drop(flag);
                if let Ok(mut quic) = conn.quic.try_lock() {
                    if !quic.is_closed() {
                        let _ = quic.close(false, 0, b"drop");
                    }
                }
            }
        }
    }
}
