//! Regression tests: RTSP FLUSH must reach the `AudioSession` immediately, even
//! when the sender stops sending RTP packets right after it (pause).

use std::sync::Arc;
use std::time::Duration;

use serial_test::serial;
use shairplay::{AudioFormat, AudioHandler, AudioSession, RaopServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

const TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, PartialEq)]
enum Event {
    Init,
    Samples(usize),
    Flush,
}

struct Capture(UnboundedSender<Event>);

impl AudioHandler for Capture {
    fn audio_init(&self, _format: AudioFormat) -> Box<dyn AudioSession> {
        let _ = self.0.send(Event::Init);
        Box::new(Capture(self.0.clone()))
    }
}

impl AudioSession for Capture {
    fn audio_process(&mut self, samples: &[f32]) {
        let _ = self.0.send(Event::Samples(samples.len()));
    }
    fn audio_flush(&mut self) {
        let _ = self.0.send(Event::Flush);
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

fn rtp_packet(seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0x60];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&(u32::from(seq) * 352).to_be_bytes());
    p.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    // 352 stereo L16 frames of silence.
    p.extend(std::iter::repeat_n(0u8, 352 * 4));
    p
}

async fn next(events: &mut UnboundedReceiver<Event>) -> Event {
    tokio::time::timeout(TIMEOUT, events.recv())
        .await
        .expect("timed out waiting for audio event")
        .unwrap()
}

/// Starts a server and an unencrypted L16 UDP session; returns the RTSP stream,
/// the data socket and the event receiver (after `Init` and one `Samples`).
async fn playing_session() -> (RaopServer, TcpStream, UdpSocket, UnboundedReceiver<Event>) {
    let (tx, mut events) = unbounded_channel();
    let mut server = RaopServer::builder()
        .name("FlushTest")
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
    let data_port: u16 = r
        .split(';')
        .find_map(|p| p.trim().strip_prefix("server_port="))
        .and_then(|p| p.split_whitespace().next())
        .unwrap()
        .parse()
        .unwrap();
    let r = rtsp(
        &mut stream,
        3,
        "RECORD",
        "RTP-Info: seq=1;rtptime=352\r\n",
        "",
    )
    .await;
    assert!(r.contains("200 OK"), "RECORD: {r}");

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(("127.0.0.1", data_port)).await.unwrap();
    assert_eq!(next(&mut events).await, Event::Init);
    udp.send(&rtp_packet(1)).await.unwrap();
    assert!(matches!(next(&mut events).await, Event::Samples(_)));
    (server, stream, udp, events)
}

#[tokio::test]
#[serial]
async fn flush_with_rtp_info_is_delivered_without_further_packets() {
    let (mut server, mut stream, _udp, mut events) = playing_session().await;
    let r = rtsp(
        &mut stream,
        4,
        "FLUSH",
        "RTP-Info: seq=2;rtptime=704\r\n",
        "",
    )
    .await;
    assert!(r.contains("200 OK"), "FLUSH: {r}");
    // No RTP packet is sent after FLUSH: the flush must still arrive.
    assert_eq!(next(&mut events).await, Event::Flush);
    server.stop().await;
}

#[tokio::test]
#[serial]
async fn flush_without_rtp_info_still_flushes() {
    let (mut server, mut stream, _udp, mut events) = playing_session().await;
    let r = rtsp(&mut stream, 4, "FLUSH", "", "").await;
    assert!(r.contains("200 OK"), "FLUSH: {r}");
    assert_eq!(next(&mut events).await, Event::Flush);
    server.stop().await;
}
