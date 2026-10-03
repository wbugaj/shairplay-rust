//! AP1 RTP audio streaming — UDP and TCP receiver with ALAC decode.
//!
//! Manages the full AP1 audio receive pipeline:
//!
//! ```text
//! iPhone → RTP/UDP or RTP/TCP → RaopRtp → RaopBuffer (decrypt+decode) → AudioSession
//! ```
//!
//! Two transport modes:
//! - **UDP** (default): data, control, and timing on separate UDP sockets.
//!   Control channel carries retransmit responses (payload type 0x56).
//! - **TCP**: single TCP connection with `$`-prefixed interleaved framing.
//!   No retransmits (reliable transport).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, mpsc, watch};
use tracing::info;

use crate::error::{NetworkError, ShairplayError};
use crate::raop::buffer::{RAOP_PACKET_LEN, RaopBuffer, StreamFormat};
use crate::raop::{AudioCodec, AudioFormat, AudioHandler};

/// RTP payload type for retransmit (RESEND) responses on the control channel.
const CTRL_PAYLOAD_TYPE: u8 = 0x56;
/// Bytes of retransmit header preceding the original RTP packet in a RESEND.
const RETRANSMIT_HEADER_LEN: usize = 4;

/// Determine the bind address for RTP sockets.
/// Uses the specific local IP for routable addresses (respects BindConfig).
/// Falls back to unspecified for link-local IPv6 — the iPhone may send RTP
/// packets from a different address than the RTSP connection used.
fn rtp_bind_addr(local: IpAddr) -> IpAddr {
    match local {
        IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80 => {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        }
        other => other,
    }
}

fn bind_udp(addr: SocketAddr) -> Result<UdpSocket, ShairplayError> {
    let socket = std::net::UdpSocket::bind(addr).map_err(NetworkError::Io)?;
    socket.set_nonblocking(true).map_err(NetworkError::Io)?;
    UdpSocket::from_std(socket)
        .map_err(NetworkError::Io)
        .map_err(Into::into)
}

fn bind_tcp(addr: SocketAddr) -> Result<TcpListener, ShairplayError> {
    let listener = std::net::TcpListener::bind(addr).map_err(NetworkError::Io)?;
    listener.set_nonblocking(true).map_err(NetworkError::Io)?;
    TcpListener::from_std(listener)
        .map_err(NetworkError::Io)
        .map_err(Into::into)
}

/// Commands from the RTSP handler to the RTP receive task.
///
/// Delivered through a channel that has its own `select!` arm, so they are
/// applied immediately — not only when the next RTP packet arrives. That
/// matters for FLUSH on pause: the sender stops sending right after it.
#[derive(Debug)]
enum RtpCommand {
    /// Drop buffered audio up to this sequence number (`-1` = everything).
    Flush(i32),
}

/// Configuration for creating an AP1 RTP session, parsed from SDP.
pub(crate) struct RtpConfig {
    /// SDP `c=` remote address string (e.g. "192.168.1.5").
    pub(crate) remote: String,
    /// Local IP address to bind sockets to.
    pub(crate) local_addr: IpAddr,
    /// SDP `a=rtpmap` attribute.
    pub(crate) rtpmap: String,
    /// Optional SDP `a=fmtp` attribute. Required for ALAC and unused for L16.
    pub(crate) fmtp: Option<String>,
    /// AES-CBC parameters when encryption was negotiated; `None` for plaintext RTP.
    pub(crate) encryption: Option<RtpEncryption>,
    /// If set, resample decoded audio to this rate.
    pub(crate) output_sample_rate: Option<u32>,
    /// Full socket address of the remote peer (preserves scope_id for link-local IPv6).
    pub(crate) remote_socket: std::net::SocketAddr,
}

/// Validated AES-CBC parameters for an encrypted RTP session.
pub(crate) struct RtpEncryption {
    pub(crate) key: [u8; 16],
    pub(crate) iv: [u8; 16],
}

/// AP1 RTP streaming session.
///
/// Owns the UDP/TCP sockets, the packet buffer, and the ALAC decoder.
/// Created when the iPhone sends the SDP ANNOUNCE. Started during RTSP SETUP,
/// which binds ports and spawns the receive task.
///
/// Dropped when the RTSP connection closes, which sends a shutdown signal
/// to the receive task via the [`watch`] channel.
pub(crate) struct RaopRtp {
    handler: Arc<dyn AudioHandler>,
    /// SDP `c=` remote address string (e.g. "192.168.1.5").
    remote: String,
    /// Local IP address to bind sockets to (matches the RTSP connection's interface).
    local_addr: IpAddr,
    /// If set, resample decoded audio to this rate before delivery.
    output_sample_rate: Option<u32>,
    /// Decoded output stream format (channels + source sample rate).
    format: StreamFormat,
    /// Shared packet buffer (decrypt + decode on queue, dequeue in order).
    buffer: Arc<Mutex<RaopBuffer>>,
    /// Commands for the receive task (sender side).
    cmd_tx: mpsc::UnboundedSender<RtpCommand>,
    /// Receiver side, moved into the receive task by [`start`](Self::start).
    cmd_rx: Option<mpsc::UnboundedReceiver<RtpCommand>>,
    /// Send `true` to shut down the receive task.
    shutdown_tx: Option<watch::Sender<bool>>,
    /// iPhone's control port (0 = no retransmits).
    control_rport: u16,
    /// Local control port (bound by us).
    pub(crate) control_lport: u16,
    /// Local timing port (bound by us).
    pub(crate) timing_lport: u16,
    /// Local data port (bound by us).
    pub(crate) data_lport: u16,
    /// Full socket address of the remote peer.
    remote_socket: std::net::SocketAddr,
}

/// Build a resampler for the AP1 RTP path: `Some` when an explicit output rate
/// differs from the source rate, otherwise `None` (native-rate passthrough).
/// Shared by the UDP and TCP receive arms of [`RaopRtp::start`].
#[cfg(feature = "resample")]
fn make_resampler(
    output_sample_rate: Option<u32>,
    src_sample_rate: u32,
    channels: usize,
) -> Option<crate::codec::resample::StreamResampler> {
    match output_sample_rate {
        Some(target) if target != src_sample_rate => {
            crate::codec::resample::StreamResampler::new(src_sample_rate, target, channels)
        }
        _ => None,
    }
}

/// Whether a resampler was actually built (always `false` without the
/// `resample` feature, where `output_sample_rate` cannot be honoured).
#[cfg(feature = "resample")]
macro_rules! resampling_active {
    ($resampler:ident) => {
        $resampler.is_some()
    };
}
#[cfg(not(feature = "resample"))]
macro_rules! resampling_active {
    ($resampler:ident) => {
        false
    };
}

/// Sample rate of the PCM actually delivered to the [`AudioSession`]: the
/// requested output rate only if a resampler is running, else the source rate.
fn delivered_sample_rate(source: u32, requested: Option<u32>, resampling: bool) -> u32 {
    match requested {
        Some(rate) if resampling => rate,
        _ => source,
    }
}

impl RaopRtp {
    /// Create a new RTP session from SDP parameters and AES session keys.
    /// Does not bind sockets or start receiving — call [`start`](Self::start) for that.
    ///
    /// Returns `None` if the peer-supplied codec configuration is unsupported or malformed.
    pub(crate) fn new(callbacks: Arc<dyn AudioHandler>, config: RtpConfig) -> Option<Self> {
        let fmtp = config.fmtp.as_deref().unwrap_or_default();
        let buffer = match config.encryption {
            Some(encryption) => {
                RaopBuffer::new(&config.rtpmap, fmtp, &encryption.key, &encryption.iv)
            }
            None => RaopBuffer::new_unencrypted(&config.rtpmap, fmtp),
        }?;
        let format = buffer.format();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        Some(Self {
            handler: callbacks,
            remote: config.remote,
            local_addr: config.local_addr,
            output_sample_rate: config.output_sample_rate,
            remote_socket: config.remote_socket,
            format,
            buffer: Arc::new(Mutex::new(buffer)),
            cmd_tx,
            cmd_rx: Some(cmd_rx),
            shutdown_tx: None,
            control_rport: 0,
            control_lport: 0,
            timing_lport: 0,
            data_lport: 0,
        })
    }

    /// Bind UDP/TCP sockets and spawn the async receive task.
    ///
    /// Returns `(control_port, timing_port, data_port)` — the local ports
    /// that the iPhone should send RTP packets to.
    ///
    /// # Transport modes
    ///
    /// - `use_udp = true`: binds 3 UDP sockets (data, control, timing).
    ///   Control channel receives retransmit responses (RTP payload type 0x56).
    /// - `use_udp = false`: binds 1 TCP listener. iPhone connects and sends
    ///   `$`-prefixed interleaved RTP frames.
    pub(crate) fn start(
        &mut self,
        use_udp: bool,
        control_rport: u16,
        timing_rport: u16,
    ) -> Result<(u16, u16, u16), ShairplayError> {
        self.control_rport = control_rport;
        info!(use_udp, control_rport, timing_rport, remote = %self.remote, "AP1 RTP starting");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);
        let cmd_rx = match self.cmd_rx.take() {
            Some(rx) => rx,
            // Restarted session: the previous task owns the old receiver.
            None => {
                let (tx, rx) = mpsc::unbounded_channel();
                self.cmd_tx = tx;
                rx
            }
        };

        if use_udp {
            let bind_addr = SocketAddr::new(rtp_bind_addr(self.local_addr), 0);
            let csock = bind_udp(bind_addr)?;
            let tsock = bind_udp(bind_addr)?;
            let dsock = bind_udp(bind_addr)?;
            self.control_lport = csock.local_addr().map_err(NetworkError::Io)?.port();
            self.timing_lport = tsock.local_addr().map_err(NetworkError::Io)?.port();
            self.data_lport = dsock.local_addr().map_err(NetworkError::Io)?.port();

            // Spawn NTP timing responder for this connection.
            let remote_sockaddr = self.remote_socket;
            let mut timing_addr = remote_sockaddr;
            timing_addr.set_port(timing_rport);
            super::ntp::spawn_ntp_responder(tsock, timing_addr);

            let format = self.format;
            #[cfg(feature = "resample")]
            let mut resampler = make_resampler(
                self.output_sample_rate,
                format.sample_rate,
                format.num_channels as usize,
            );
            let mut session = self.handler.audio_init(AudioFormat {
                codec: AudioCodec::Pcm,
                bits: 32,
                channels: format.num_channels,
                sample_rate: delivered_sample_rate(
                    format.sample_rate,
                    self.output_sample_rate,
                    resampling_active!(resampler),
                ),
            });

            let buffer = self.buffer.clone();
            // If control_rport is 0, the iPhone doesn't support retransmits.
            let no_resend = control_rport == 0;
            let _remote_for_task = self.remote.clone();

            tokio::spawn(async move {
                let mut shutdown_rx = shutdown_rx;
                let mut cmd_rx = cmd_rx;
                let mut data_packet = [0u8; RAOP_PACKET_LEN];
                let mut ctrl_packet = [0u8; RAOP_PACKET_LEN];
                loop {
                    tokio::select! {
                        Some(cmd) = cmd_rx.recv() => match cmd {
                            RtpCommand::Flush(seq) => {
                                buffer.lock().await.flush(seq);
                                session.audio_flush();
                            }
                        },
                        // Data channel: audio RTP packets.
                        result = dsock.recv_from(&mut data_packet) => {
                            if let Ok((len, _)) = result
                                && len >= 12 {
                                    let mut buf = buffer.lock().await;
                                    buf.queue(&data_packet[..len], true);
                                    while let Some(samples) = buf.dequeue(no_resend) {
                                        {
                                            #[cfg(feature = "resample")]
                                            if let Some(ref mut rs) = resampler {
                                                let resampled = rs.process(samples);
                                                session.audio_process(&resampled);
                                            } else {
                                                session.audio_process(samples);
                                            }
                                            #[cfg(not(feature = "resample"))]
                                            session.audio_process(samples);
                                        }
                                    }
                                }
                        }
                        // Control channel: retransmit responses (payload type 0x56).
                        result = csock.recv_from(&mut ctrl_packet) => {
                            if let Ok((len, _)) = result
                                && len >= 12 && (ctrl_packet[1] & !0x80) == CTRL_PAYLOAD_TYPE {
                                    let mut buf = buffer.lock().await;
                                    // Retransmit packets have a 4-byte header before the original RTP.
                                    if len > RETRANSMIT_HEADER_LEN { buf.queue(&ctrl_packet[RETRANSMIT_HEADER_LEN..len], true); }
                                }
                        }
                        _ = shutdown_rx.changed() => break,
                    }
                }
                // AudioSession dropped here → triggers cleanup in the app.
            });
        } else {
            // TCP interleaved mode: single connection, `$`-prefixed framing.
            let listener = bind_tcp(SocketAddr::new(rtp_bind_addr(self.local_addr), 0))?;
            self.data_lport = listener.local_addr().map_err(NetworkError::Io)?.port();

            let format = self.format;
            #[cfg(feature = "resample")]
            let mut resampler = make_resampler(
                self.output_sample_rate,
                format.sample_rate,
                format.num_channels as usize,
            );
            let mut session = self.handler.audio_init(AudioFormat {
                codec: AudioCodec::Pcm,
                bits: 32,
                channels: format.num_channels,
                sample_rate: delivered_sample_rate(
                    format.sample_rate,
                    self.output_sample_rate,
                    resampling_active!(resampler),
                ),
            });

            let buffer = self.buffer.clone();
            let _remote_for_tcp = self.remote.clone();

            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut shutdown_rx = shutdown_rx;
                let mut cmd_rx = cmd_rx;

                // Wait for the iPhone to connect.
                let stream = tokio::select! {
                    result = listener.accept() => match result {
                        Ok((s, _)) => s,
                        Err(_) => return,
                    },
                    _ = shutdown_rx.changed() => return,
                };

                let mut reader = tokio::io::BufReader::new(stream);
                let mut packet_buf = Vec::with_capacity(RAOP_PACKET_LEN + 4);
                let mut read_buf = [0u8; 4096];

                'tcp: loop {
                    tokio::select! {
                        Some(cmd) = cmd_rx.recv() => match cmd {
                            RtpCommand::Flush(seq) => {
                                buffer.lock().await.flush(seq);
                                session.audio_flush();
                            }
                        },
                        result = reader.read(&mut read_buf) => {
                            match result {
                                Ok(0) | Err(_) => break,
                                Ok(n) => packet_buf.extend_from_slice(&read_buf[..n]),
                            }
                            if packet_buf.len() > RAOP_PACKET_LEN * 4 {
                                tracing::warn!("TCP RTP buffer exceeded safety limit");
                                break;
                            }
                            // TCP interleaved: each frame is `$ <channel> <len_hi> <len_lo> <rtp...>`.
                            while packet_buf.len() >= 4 {
                                if packet_buf[0] != b'$' || packet_buf[1] != 0 {
                                    packet_buf.drain(..1);
                                    continue;
                                }
                                let rtp_len = ((packet_buf[2] as usize) << 8) | packet_buf[3] as usize;
                                if rtp_len > RAOP_PACKET_LEN {
                                    tracing::warn!(rtp_len, "TCP RTP frame exceeded maximum size, closing");
                                    packet_buf.clear();
                                    break 'tcp;
                                }
                                if packet_buf.len() < 4 + rtp_len { break; }
                                let mut buf = buffer.lock().await;
                                buf.queue(&packet_buf[4..4 + rtp_len], false);
                                if let Some(samples) = buf.dequeue(true) {
                                    {
                                            #[cfg(feature = "resample")]
                                            if let Some(ref mut rs) = resampler {
                                                let resampled = rs.process(samples);
                                                session.audio_process(&resampled);
                                            } else {
                                                session.audio_process(samples);
                                            }
                                            #[cfg(not(feature = "resample"))]
                                            session.audio_process(samples);
                                        }
                                }
                                drop(buf);
                                packet_buf.drain(..4 + rtp_len);
                            }
                        }
                        _ = shutdown_rx.changed() => break,
                    }
                }
            });
        }

        Ok((self.control_lport, self.timing_lport, self.data_lport))
    }

    /// Request a buffer flush up to the given sequence number.
    pub(crate) fn flush(&self, next_seq: i32) {
        // Fails only if the receive task has ended; nothing left to flush then.
        let _ = self.cmd_tx.send(RtpCommand::Flush(next_seq));
    }

    /// Stop the receive task and flush the buffer.
    pub(crate) fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        self.flush(-1);
    }
}

#[cfg(test)]
mod tests {
    use super::delivered_sample_rate;

    #[test]
    fn announces_output_rate_only_when_resampling() {
        assert_eq!(delivered_sample_rate(44_100, Some(48_000), true), 48_000);
        assert_eq!(delivered_sample_rate(44_100, Some(48_000), false), 44_100);
        assert_eq!(delivered_sample_rate(44_100, None, false), 44_100);
        assert_eq!(delivered_sample_rate(44_100, None, true), 44_100);
    }
}
