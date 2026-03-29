mod message;
use message::Message;

use airnomads::{
    H3Client, QuicConfig,
    error::{H3Error, Result},
    realtime::RealtimeMode,
};

use std::net::AddrParseError;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info,quic_h3=debug")
        .init();

    let client = H3Client::new(
        "127.0.0.1:4433"
            .parse()
            .map_err(|e: AddrParseError| H3Error::AddrErr(e.to_string()))?,
        "0.0.0.0:3344"
            .parse()
            .map_err(|e: AddrParseError| H3Error::AddrErr(e.to_string()))?,
        QuicConfig::new().with_cert("./cert.pem", "./key.pem"), // dev
        "quic.dev",
    );

    let conn = client.connect().await?;
    conn.handshake().await?;

    info!("=== HTTP/3 GET / ===");
    let resp = conn.get("/").await?;
    info!("Status: {}", resp.status);
    info!("Body: {}", String::from_utf8_lossy(&resp.body));

    info!("=== HTTP/3 POST /echo ===");

    let mut buf = Vec::new();
    let data = Message {
        status: 200,
        data: "Hello world".to_string(),
    };
    serde_json::to_writer(&mut buf, &data)?;
    let resp = conn.post_json("/echo", Some(&buf)).await?;

    info!(
        "Echo Response body: {}",
        String::from_utf8_lossy(&resp.body)
    );

    info!("=== Realtime: joining channel 'chat' ===");
    let stream = conn
        .realtime_connect("chat", RealtimeMode::Reliable)
        .await?;

    let (tx_stream, mut rx_stream) = stream.split();

    tokio::spawn(async move {
        info!("=== Listening for incoming realtime messages... ===");
        while let Some(msg) = rx_stream.recv().await {
            let buf = msg.payload;

            info!(
                "[Realtime In] event='{}' payload={:?}",
                msg.event,
                String::from_utf8_lossy(&buf)
            );
        }
        info!("Listener task closed.");
    });

    for i in 0..9 {
        let mut buf = Vec::new();
        let data: Message = Message {
            status: 200,
            data: format!("Hello #{}", i).to_string(),
        };

        serde_json::to_writer(&mut buf, &data)?;
        tx_stream.send("message", buf).await?;
        info!("[Realtime Out] Sent message #{}", i);

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    tx_stream.send("leave", Vec::new()).await?;

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    Ok(())
}
