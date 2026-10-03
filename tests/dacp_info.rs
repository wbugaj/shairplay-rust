//! `on_dacp_info` must be delivered inline from AP1 SETUP, and the built-in DACP
//! discovery (a blocking mDNS lookup) must not delay the SETUP response.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serial_test::serial;
use shairplay::{AudioFormat, AudioHandler, AudioSession, DacpInfo, RaopServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Default)]
struct Capture {
    infos: Mutex<Vec<DacpInfo>>,
}

struct Silent;
impl AudioSession for Silent {
    fn audio_process(&mut self, _samples: &[f32]) {}
}

impl AudioHandler for Capture {
    fn audio_init(&self, _format: AudioFormat) -> Box<dyn AudioSession> {
        Box::new(Silent)
    }
    fn on_dacp_info(&self, info: &DacpInfo) {
        self.infos.lock().unwrap().push(info.clone());
    }
}

async fn rtsp(stream: &mut TcpStream, cseq: u32, method: &str, extra: &str, body: &str) -> String {
    let req = format!(
        "{method} rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: {cseq}\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

async fn setup_with_dacp(discovery: bool) -> (Arc<Capture>, Duration) {
    let handler = Arc::new(Capture::default());
    let mut server = RaopServer::builder()
        .name("DacpInfoTest")
        .port(0)
        .dacp_discovery(discovery)
        .build(handler.clone())
        .unwrap();
    server.start().await.unwrap();
    let port = server.service_info().port;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    let sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=test\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 0 RTP/AVP 96\r\na=rtpmap:96 L16/44100/2\r\n";
    let r = rtsp(
        &mut stream,
        1,
        "ANNOUNCE",
        "Content-Type: application/sdp\r\n",
        sdp,
    )
    .await;
    assert!(r.contains("200 OK"), "ANNOUNCE: {r}");

    let started = Instant::now();
    let r = rtsp(
        &mut stream,
        2,
        "SETUP",
        "Transport: RTP/AVP/UDP;unicast;mode=record;control_port=0;timing_port=0\r\n\
         DACP-ID: 7711DA8B47838CB5\r\nActive-Remote: 1986535575\r\nUser-Agent: AirPlay/960.13.1\r\n",
        "",
    )
    .await;
    let elapsed = started.elapsed();
    assert!(r.contains("200 OK"), "SETUP: {r}");
    server.stop().await;
    (handler, elapsed)
}

#[tokio::test]
#[serial]
async fn setup_reports_dacp_info_inline() {
    let (handler, _) = setup_with_dacp(false).await;
    let infos = handler.infos.lock().unwrap();
    assert_eq!(infos.len(), 1);
    let info = &infos[0];
    assert_eq!(info.dacp_id, "7711DA8B47838CB5");
    assert_eq!(info.active_remote, "1986535575");
    assert_eq!(info.user_agent.as_deref(), Some("AirPlay/960.13.1"));
    assert_eq!(info.peer.ip().to_string(), "127.0.0.1");
}

#[tokio::test]
#[serial]
async fn dacp_discovery_does_not_delay_setup() {
    // Nothing answers `_dacp._tcp` here, so a blocking lookup would take ~2 s.
    let (handler, elapsed) = setup_with_dacp(true).await;
    assert_eq!(handler.infos.lock().unwrap().len(), 1);
    assert!(
        elapsed < Duration::from_millis(1000),
        "SETUP took {elapsed:?}"
    );
}
