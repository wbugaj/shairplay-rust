//! NTP timing for AirPlay legacy (AP1) connections.
//!
//! Sends timing requests (0x52) to the sender, answers the sender's requests,
//! and turns the sender's replies (0x53) into a clock offset estimate, so the
//! RTP layer can map sender NTP times (SYNC packets) onto the local clock.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

/// Seconds between the NTP epoch (1900-01-01) and the UNIX epoch (1970-01-01).
const NTP_UNIX_EPOCH_OFFSET_SECS: u64 = 0x83AA_7E80; // 2_208_988_800

/// Number of recent offset samples the estimate is chosen from.
const CLOCK_FILTER_LEN: usize = 8;

/// Interval between timing requests once the initial burst has been sent.
const REQUEST_INTERVAL: Duration = Duration::from_secs(3);

/// A 64-bit NTP timestamp (32.32 fixed point, seconds since 1900).
pub(crate) type NtpTime = u64;

/// Current local time as an NTP timestamp.
pub(crate) fn ntp_now() -> NtpTime {
    system_time_to_ntp(SystemTime::now())
}

pub(crate) fn system_time_to_ntp(t: SystemTime) -> NtpTime {
    let since_unix = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since_unix.as_secs() + NTP_UNIX_EPOCH_OFFSET_SECS;
    let frac = (u64::from(since_unix.subsec_nanos()) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

/// Signed difference `a - b` in nanoseconds.
pub(crate) fn ntp_diff_ns(a: NtpTime, b: NtpTime) -> i128 {
    let to_ns = |t: NtpTime| -> i128 {
        let secs = i128::from(t >> 32);
        let frac = i128::from(t & 0xFFFF_FFFF);
        secs * 1_000_000_000 + ((frac * 1_000_000_000) >> 32)
    };
    to_ns(a) - to_ns(b)
}

fn read_ntp(buf: &[u8], off: usize) -> NtpTime {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_be_bytes(b)
}

fn put_ntp(buf: &mut [u8], off: usize, t: NtpTime) {
    buf[off..off + 8].copy_from_slice(&t.to_be_bytes());
}

/// Offset between the sender's clock and ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClockEstimate {
    /// `sender_time - local_time`, in nanoseconds.
    pub(crate) offset_ns: i128,
    /// Round-trip time of the sample this estimate came from.
    pub(crate) rtt_ns: i128,
}

/// Classic NTP offset/delay from one exchange:
/// `t1` our send, `t2` sender receive, `t3` sender send, `t4` our receive.
pub(crate) fn estimate(t1: NtpTime, t2: NtpTime, t3: NtpTime, t4: NtpTime) -> ClockEstimate {
    let offset_ns = i128::midpoint(ntp_diff_ns(t2, t1), ntp_diff_ns(t3, t4));
    let rtt_ns = ntp_diff_ns(t4, t1) - ntp_diff_ns(t3, t2);
    ClockEstimate { offset_ns, rtt_ns }
}

/// Keeps the last few samples and picks the one with the smallest round trip:
/// Wi-Fi delays are asymmetric spikes, and the fastest exchange is the least
/// distorted (standard NTP clock filter).
#[derive(Debug, Default)]
pub(crate) struct ClockFilter {
    samples: Vec<ClockEstimate>,
}

impl ClockFilter {
    pub(crate) fn add(&mut self, sample: ClockEstimate) -> Option<ClockEstimate> {
        if sample.rtt_ns < 0 {
            return self.best();
        }
        if self.samples.len() == CLOCK_FILTER_LEN {
            self.samples.remove(0);
        }
        self.samples.push(sample);
        self.best()
    }

    pub(crate) fn best(&self) -> Option<ClockEstimate> {
        self.samples.iter().min_by_key(|s| s.rtt_ns).copied()
    }
}

/// Parsed timing reply (payload type 0x53).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TimingReply {
    pub(crate) origin: NtpTime,
    pub(crate) receive: NtpTime,
    pub(crate) transmit: NtpTime,
}

pub(crate) fn parse_timing_reply(buf: &[u8]) -> Option<TimingReply> {
    if buf.len() < 32 || buf[1] & 0x7f != 0x53 {
        return None;
    }
    Some(TimingReply {
        origin: read_ntp(buf, 8),
        receive: read_ntp(buf, 16),
        transmit: read_ntp(buf, 24),
    })
}

fn timing_request(now: NtpTime) -> [u8; 32] {
    let mut req = [0u8; 32];
    req[0] = 0x80;
    req[1] = 0xd2;
    req[3] = 0x07;
    put_ntp(&mut req, 24, now);
    req
}

/// Spawns the timing task for one RTP session. It ends when `shutdown` changes
/// or its sender is dropped (`None` = runs until the socket task is dropped).
/// Clock estimates are published on `clock`.
pub(crate) fn spawn_ntp_responder(
    tsock: tokio::net::UdpSocket,
    remote_timing: std::net::SocketAddr,
    clock: watch::Sender<Option<ClockEstimate>>,
    mut shutdown: Option<watch::Receiver<bool>>,
) {
    tokio::spawn(async move {
        let mut buf = [0u8; 128];
        let mut filter = ClockFilter::default();
        let can_request = remote_timing.port() > 0;

        if can_request {
            tracing::debug!(%remote_timing, "NTP: sending initial timing requests");
            for _ in 0..3 {
                let _ = tsock
                    .send_to(&timing_request(ntp_now()), remote_timing)
                    .await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        let mut interval = tokio::time::interval(REQUEST_INTERVAL);
        interval.tick().await; // first tick fires immediately
        loop {
            tokio::select! {
                result = tsock.recv_from(&mut buf) => {
                    let received = ntp_now();
                    match result {
                        Ok((len, addr)) if len >= 32 && buf[1] & 0x7f == 0x52 => {
                            // Timing request from the sender — answer it.
                            let mut resp = [0u8; 32];
                            resp.copy_from_slice(&buf[..32]);
                            resp[1] = 0xd3;
                            resp[8..16].copy_from_slice(&buf[24..32]);
                            put_ntp(&mut resp, 16, received);
                            put_ntp(&mut resp, 24, ntp_now());
                            let _ = tsock.send_to(&resp, addr).await;
                        }
                        Ok((len, _)) => {
                            if let Some(reply) = parse_timing_reply(&buf[..len]) {
                                let sample = estimate(reply.origin, reply.receive, reply.transmit, received);
                                if let Some(best) = filter.add(sample) {
                                    tracing::trace!(
                                        offset_ns = sample.offset_ns as i64,
                                        rtt_us = (sample.rtt_ns / 1000) as i64,
                                        best_offset_ns = best.offset_ns as i64,
                                        "NTP timing reply"
                                    );
                                    clock.send_replace(Some(best));
                                }
                            }
                        }
                        // Windows reports ICMP "port unreachable" from a previous
                        // send as WSAECONNRESET on the next receive; the socket
                        // is still usable, so keep going.
                        Err(error) => tracing::trace!(%error, "NTP: receive error ignored"),
                    }
                }
                _ = interval.tick(), if can_request => {
                    let _ = tsock.send_to(&timing_request(ntp_now()), remote_timing).await;
                }
                _ = async {
                    match shutdown.as_mut() {
                        Some(rx) => { let _ = rx.changed().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => break,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1 << 32;

    #[test]
    fn diff_handles_fractions_and_sign() {
        let a = 10 * SEC + SEC / 2; // 10.5 s
        let b = 10 * SEC;
        assert_eq!(ntp_diff_ns(a, b), 500_000_000);
        assert_eq!(ntp_diff_ns(b, a), -500_000_000);
    }

    #[test]
    fn symmetric_exchange_gives_exact_offset() {
        // Sender clock is 100 s ahead; 10 ms each way; sender holds 1 ms.
        let ms = SEC / 1000;
        let t1 = 1000 * SEC;
        let t2 = t1 + 100 * SEC + 10 * ms;
        let t3 = t2 + ms;
        let t4 = t1 + 21 * ms;
        let e = estimate(t1, t2, t3, t4);
        assert!((e.offset_ns - 100_000_000_000).abs() < 1_000, "{e:?}");
        assert!((e.rtt_ns - 20_000_000).abs() < 1_000, "{e:?}");
    }

    #[test]
    fn filter_prefers_lowest_rtt_and_forgets_old_samples() {
        let mut f = ClockFilter::default();
        f.add(ClockEstimate {
            offset_ns: 5,
            rtt_ns: 50,
        });
        f.add(ClockEstimate {
            offset_ns: 7,
            rtt_ns: 10,
        });
        assert_eq!(f.best().unwrap().offset_ns, 7);
        // A negative RTT is bogus and ignored.
        f.add(ClockEstimate {
            offset_ns: 99,
            rtt_ns: -1,
        });
        assert_eq!(f.best().unwrap().offset_ns, 7);
        for i in 0..CLOCK_FILTER_LEN {
            f.add(ClockEstimate {
                offset_ns: 100 + i as i128,
                rtt_ns: 30,
            });
        }
        assert_eq!(f.best().unwrap().offset_ns, 100, "old best aged out");
    }

    #[test]
    fn parses_timing_reply() {
        let mut p = [0u8; 32];
        p[0] = 0x80;
        p[1] = 0xd3;
        put_ntp(&mut p, 8, 1);
        put_ntp(&mut p, 16, 2);
        put_ntp(&mut p, 24, 3);
        assert_eq!(
            parse_timing_reply(&p),
            Some(TimingReply {
                origin: 1,
                receive: 2,
                transmit: 3
            })
        );
        p[1] = 0xd2;
        assert_eq!(parse_timing_reply(&p), None);
        assert_eq!(parse_timing_reply(&p[..20]), None);
    }

    #[test]
    fn request_carries_transmit_time() {
        let r = timing_request(42);
        assert_eq!(r[1], 0xd2);
        assert_eq!(read_ntp(&r, 24), 42);
    }
}
