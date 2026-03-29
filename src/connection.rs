use bytes::BytesMut;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tracing::debug;

use crate::error::{H3Error, Result};
use crate::realtime::{RealtimeEvent, RealtimeMessage};

#[derive(Debug, Clone, PartialEq)]
pub enum StreamType {
    Http3,
    Realtime,
}

pub struct StreamMeta {
    pub stream_id: u64,
    pub stream_type: StreamType,
    pub channel: Option<String>,
    pub buffer: BytesMut,
}

pub struct QuicConnection {
    pub conn_id: String,
    pub peer_addr: SocketAddr,
    pub(crate) quic: Arc<Mutex<quiche::Connection>>,
    pub(crate) h3: Arc<Mutex<Option<quiche::h3::Connection>>>,
    pub(crate) realtime_tx: mpsc::Sender<RealtimeEvent>,
    pub(crate) streams: Arc<Mutex<HashMap<u64, StreamMeta>>>,
}

impl QuicConnection {
    pub fn new(
        conn_id: String,
        peer_addr: SocketAddr,
        quic: quiche::Connection,
        realtime_tx: mpsc::Sender<RealtimeEvent>,
    ) -> Self {
        Self {
            conn_id,
            peer_addr,
            quic: Arc::new(Mutex::new(quic)),
            h3: Arc::new(Mutex::new(None)),
            realtime_tx,
            streams: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn is_established(&self) -> bool {
        self.quic.lock().await.is_established()
    }

    pub async fn is_closed(&self) -> bool {
        self.quic.lock().await.is_closed()
    }

    pub async fn init_h3_server(&self) -> Result<()> {
        let h3_config = quiche::h3::Config::new()?;
        let mut quic = self.quic.lock().await;
        let h3 = quiche::h3::Connection::with_transport(&mut *quic, &h3_config)?;
        *self.h3.lock().await = Some(h3);
        debug!("H3 connection initialized (server) for {}", self.conn_id);
        Ok(())
    }

    pub async fn init_h3_client(&self) -> Result<()> {
        let mut h3_config = quiche::h3::Config::new()?;
        h3_config.set_max_field_section_size(8192);
        h3_config.enable_extended_connect(true);

        let mut quic = self.quic.lock().await;
        let h3 = quiche::h3::Connection::with_transport(&mut *quic, &h3_config)?;
        *self.h3.lock().await = Some(h3);
        debug!("H3 connection initialized (client) for {}", self.conn_id);
        Ok(())
    }

    pub async fn send_h3_response(
        &self,
        stream_id: u64,
        headers: &[quiche::h3::Header],
        body: Option<&[u8]>,
    ) -> Result<()> {
        let mut quic = self.quic.lock().await;
        let mut h3_guard = self.h3.lock().await;
        let h3 = h3_guard.as_mut().ok_or(H3Error::ConnectionClosed)?;

        h3.send_response(&mut *quic, stream_id, headers, body.is_none())?;

        if let Some(data) = body {
            h3.send_body(&mut *quic, stream_id, data, true)?;
        }

        Ok(())
    }

    pub async fn open_realtime_stream(&self, stream_id: u64, channel: &str) -> Result<u64> {
        let mut quic = self.quic.lock().await;

        let handshake = RealtimeMessage::new("join", channel, vec![]);
        let mut buf = Vec::new();
        serde_json::to_writer(&mut buf, &handshake)?;

        let len_prefix = (buf.len() as u32).to_be_bytes();

        quic.stream_send(stream_id, &len_prefix, false)?;
        quic.stream_send(stream_id, &buf, false)?;

        let mut streams = self.streams.lock().await;
        streams.insert(
            stream_id,
            StreamMeta {
                stream_id,
                stream_type: StreamType::Realtime,
                channel: Some(channel.to_string()),
                buffer: BytesMut::with_capacity(8192),
            },
        );

        debug!(
            "opened realtime stream {} for channel '{}'",
            stream_id, channel
        );

        Ok(stream_id)
    }

    pub async fn send_realtime(&self, stream_id: u64, msg: &RealtimeMessage) -> Result<()> {
        let mut quic = self.quic.lock().await;
        let mut encoded: Vec<u8> = Vec::new();

        serde_json::to_writer(&mut encoded, &msg)?;
        let len = (encoded.len() as u32).to_be_bytes();
        quic.stream_send(stream_id, &len, false)?;
        quic.stream_send(stream_id, &encoded, false)?;
        Ok(())
    }

    pub async fn close_stream(&self, stream_id: u64) -> Result<()> {
        let mut quic = self.quic.lock().await;
        quic.stream_send(stream_id, b"", true)?;
        self.streams.lock().await.remove(&stream_id);
        Ok(())
    }

    pub fn generate_conn_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }
}
