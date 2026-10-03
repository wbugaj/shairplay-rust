//! The AP1 RECORD response reports the configured `Audio-Latency`.

use std::sync::Arc;
use std::time::Duration;

use serial_test::serial;
use shairplay::{AudioFormat, AudioHandler, AudioSession, RaopServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Silent;
impl AudioSession for Silent {
    fn audio_process(&mut self, _samples: &[f32]) {}
}
impl AudioHandler for Silent {
    fn audio_init(&self, _format: AudioFormat) -> Box<dyn AudioSession> {
        Box::new(Silent)
    }
}

async fn record_response(builder: shairplay::RaopServerBuilder) -> String {
    let mut server = builder.port(0).build(Arc::new(Silent)).unwrap();
    server.start().await.unwrap();
    let port = server.service_info().port;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(b"RECORD rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: 1\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    server.stop().await;
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[tokio::test]
#[serial]
async fn record_reports_zero_latency_by_default() {
    let r = record_response(RaopServer::builder().name("LatencyDefault")).await;
    assert!(r.contains("\r\nAudio-Latency: 0\r\n"), "got: {r}");
}

#[tokio::test]
#[serial]
async fn record_reports_configured_latency() {
    let r = record_response(RaopServer::builder().name("Latency").audio_latency(11025)).await;
    assert!(r.contains("\r\nAudio-Latency: 11025\r\n"), "got: {r}");
}
