use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, info};

use crate::error::{H3Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeMessage {
    pub event: String,
    pub channel: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RealtimeMode {
    Unrealible,
    Reliable,
}

impl RealtimeMessage {
    pub fn new(event: impl Into<String>, channel: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            event: event.into(),
            channel: channel.into(),
            payload,
        }
    }
}

#[derive(Debug, Clone)]
pub enum RealtimeEvent {
    Join {
        conn_id: String,
        channel: String,
        stream_id: u64,
    },
    Leave {
        conn_id: String,
        channel: String,
    },
    Message {
        conn_id: String,
        stream_id: u64,
        msg: RealtimeMessage,
    },
    Disconnected {
        conn_id: String,
    },
}

type Subscriber = mpsc::Sender<bytes::Bytes>;

pub struct RealtimeChannel {
    channels: Arc<RwLock<HashMap<String, HashMap<String, Subscriber>>>>,
}

impl RealtimeChannel {
    pub fn new() -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn subscribe(&self, channel: &str, conn_id: &str) -> mpsc::Receiver<bytes::Bytes> {
        let (tx, rx) = mpsc::channel(256);
        let mut chans = self.channels.write().await;
        chans
            .entry(channel.to_string())
            .or_default()
            .insert(conn_id.to_string(), tx);
        info!("Conn '{}' subscribed to channel '{}'", conn_id, channel);
        rx
    }

    pub async fn unsubscribe(&self, channel: &str, conn_id: &str) {
        let mut chans = self.channels.write().await;
        if let Some(subs) = chans.get_mut(channel) {
            subs.remove(conn_id);
            if subs.is_empty() {
                chans.remove(channel);
            }
        }
        debug!("Conn '{}' unsubscribed from channel '{}'", conn_id, channel);
    }

    pub async fn broadcast(
        &self,
        channel: &str,
        msg: RealtimeMessage,
        exclude_conn: Option<&str>,
    ) -> usize {
        let chans = self.channels.read().await;
        let Some(subs) = chans.get(channel) else {
            return 0;
        };

        let encoded_vec = match crate::realtime::encode_realtime_frame(&msg) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("failed encode broadcast: {}", e);
                return 0;
            }
        };

        let shared_frame = bytes::Bytes::from(encoded_vec);

        let mut sent = 0;
        for (conn_id, tx) in subs.iter() {
            if let Some(exc) = exclude_conn {
                if conn_id == exc {
                    continue;
                }
            }

            if tx.send(shared_frame.clone()).await.is_ok() {
                sent += 1;
            }
        }
        sent
    }

    pub async fn send_to(&self, channel: &str, conn_id: &str, msg: bytes::Bytes) -> Result<()> {
        let chans = self.channels.read().await;
        let subs = chans
            .get(channel)
            .ok_or_else(|| H3Error::ChannelNotFound(channel.to_string()))?;
        let tx = subs
            .get(conn_id)
            .ok_or_else(|| H3Error::ChannelNotFound(conn_id.to_string()))?;
        tx.send(msg).await.map_err(|_| H3Error::ConnectionClosed)?;
        Ok(())
    }

    pub async fn subscribers(&self, channel: &str) -> Vec<String> {
        let chans = self.channels.read().await;
        chans
            .get(channel)
            .map(|s| s.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub async fn active_channels(&self) -> Vec<String> {
        self.channels.read().await.keys().cloned().collect()
    }

    pub fn clone_handle(&self) -> Self {
        Self {
            channels: Arc::clone(&self.channels),
        }
    }
}

impl Default for RealtimeChannel {
    fn default() -> Self {
        Self::new()
    }
}

pub fn parse_realtime_frame(buf: &[u8]) -> Option<(RealtimeMessage, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return None;
    }
    let json = &buf[4..4 + len];
    let msg = serde_json::from_slice(json).ok()?;
    Some((msg, 4 + len))
}

pub fn encode_realtime_frame(msg: &RealtimeMessage) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(msg)?;
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

/*
* TODO: Web transport standart ietf
*/
pub fn encode_quic_varint(val: u64) -> Vec<u8> {
    if val <= 0x3F {
        vec![val as u8]
    } else if val <= 0x3FFF {
        let mut buf = vec![0; 2];
        buf[0] = 0x40 | ((val >> 8) as u8);
        buf[1] = (val & 0xFF) as u8;
        buf
    } else if val <= 0x3FFFFFFF {
        let mut buf = vec![0; 4];
        buf[0] = 0x80 | ((val >> 24) as u8);
        buf[1] = ((val >> 16) & 0xFF) as u8;
        buf[2] = ((val >> 8) & 0xFF) as u8;
        buf[3] = (val & 0xFF) as u8;
        buf
    } else {
        let mut buf = vec![0; 8];
        buf[0] = 0xC0 | ((val >> 56) as u8);
        buf[1] = ((val >> 48) & 0xFF) as u8;
        buf[2] = ((val >> 40) & 0xFF) as u8;
        buf[3] = ((val >> 32) & 0xFF) as u8;
        buf[4] = ((val >> 24) & 0xFF) as u8;
        buf[5] = ((val >> 16) & 0xFF) as u8;
        buf[6] = ((val >> 8) & 0xFF) as u8;
        buf[7] = (val & 0xFF) as u8;
        buf
    }
}

pub fn decode_quic_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }

    let prefix = buf[0] >> 6;
    let length = 1 << prefix;

    if buf.len() < length {
        return None;
    }

    let mut val = (buf[0] & 0x3F) as u64;
    for i in 1..length {
        val = (val << 8) | (buf[i] as u64);
    }

    Some((val, length))
}
