//! End to end: RTP timestamps reach `audio_process_timed`, and a SYNC packet on
//! the control port reaches `on_playout_anchor`.

use std::sync::Arc;
use std::time::Duration;

use serial_test::serial;
use shairplay::{
    AudioFormat, AudioHandler, AudioSession, ClockSource, FrameTiming, PlayoutAnchor, RaopServer,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

const TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
enum Event {
    Init,
    Timed(FrameTiming),
    Anchor(PlayoutAnchor),
}

struct Capture(UnboundedSender<Event>);

impl AudioHandler for Capture {
    fn audio_init(&self, _format: AudioFormat) -> Box<dyn AudioSession> {
        let _ = self.0.send(Event::Init);
        Box::new(Capture(self.0.clone()))
    }
}

impl AudioSession for Capture {
    fn audio_process(&mut self, _samples: &[f32]) {
        panic!("audio_process_timed is overridden; audio_process must not be called");
    }
    fn audio_process_timed(&mut self, _samples: &[f32], timing: FrameTiming) {
        let _ = self.0.send(Event::Timed(timing));
    }
    fn on_playout_anchor(&mut self, anchor: PlayoutAnchor) {
        let _ = self.0.send(Event::Anchor(anchor));
    }
}

async fn rtsp(stream: &mut TcpStream, cseq: u32, method: &str, extra: &str, body: &str) -> String {
    let req = format!(
        "{method} rtsp://127.0.0.1/stream RTSP/1.0\r\nCSeq: {cseq}\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(TIMEOUT, stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

fn transport_port(response: &str, key: &str) -> u16 {
    response
        .split([';', '\r', '\n'])
        .find_map(|p| p.trim().strip_prefix(key))
        .unwrap()
        .parse()
        .unwrap()
}

async fn next(events: &mut UnboundedReceiver<Event>) -> Event {
    tokio::time::timeout(TIMEOUT, events.recv())
        .await
        .expect("timed out waiting for event")
        .unwrap()
}

#[tokio::test]
#[serial]
async fn timestamps_and_sync_anchor_are_delivered() {
    let (tx, mut events) = unbounded_channel();
    let mut server = RaopServer::builder()
        .name("TimingTest")
        .port(0)
        .build(Arc::new(Capture(tx)))
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
    let r = rtsp(
        &mut stream,
        2,
        "SETUP",
        "Transport: RTP/AVP/UDP;unicast;mode=record;control_port=0;timing_port=0\r\n",
        "",
    )
    .await;
    assert!(r.contains("200 OK"), "SETUP: {r}");
    let data_port = transport_port(&r, "server_port=");
    let control_port = transport_port(&r, "control_port=");
    assert_eq!(next(&mut events).await.discriminant(), "init");

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // One L16 packet: seq 7, RTP timestamp 123456.
    let mut pkt = vec![0x80, 0x60, 0x00, 0x07];
    pkt.extend_from_slice(&123_456u32.to_be_bytes());
    pkt.extend_from_slice(&[0, 0, 0, 1]);
    pkt.extend(std::iter::repeat_n(0u8, 352 * 4));
    udp.send_to(&pkt, ("127.0.0.1", data_port)).await.unwrap();
    match next(&mut events).await {
        Event::Timed(t) => assert_eq!((t.rtp_ts, t.seq, t.silence), (123_456, 7, false)),
        other => panic!("expected timed audio, got {other:?}"),
    }

    // First SYNC: RTP now−latency 100000, RTP now 188200 (2 s latency).
    let mut sync = vec![0x90, 0xd4, 0x00, 0x07];
    sync.extend_from_slice(&100_000u32.to_be_bytes());
    sync.extend_from_slice(&(1u64 << 32).to_be_bytes());
    sync.extend_from_slice(&188_200u32.to_be_bytes());
    udp.send_to(&sync, ("127.0.0.1", control_port))
        .await
        .unwrap();
    match next(&mut events).await {
        Event::Anchor(a) => {
            assert_eq!(a.rtp_ts, 100_000);
            assert_eq!(a.latency_frames, 88_200);
            assert!(a.first);
            // No timing port was given, so no NTP estimate exists.
            assert_eq!(a.clock, ClockSource::Arrival);
        }
        other => panic!("expected anchor, got {other:?}"),
    }
    server.stop().await;
}

impl Event {
    fn discriminant(&self) -> &'static str {
        match self {
            Event::Init => "init",
            Event::Timed(_) => "timed",
            Event::Anchor(_) => "anchor",
        }
    }
}
