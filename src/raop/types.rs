//! Public types and traits for the AirPlay server.

use std::sync::Arc;

/// Runtime protocol mode selection.
///
/// When the `ap2` feature is enabled, this controls whether the server
/// advertises itself as an AirPlay 1 (classic) or AirPlay 2 receiver.
/// Both modes share the same RTSP listener — the difference is in mDNS
/// advertisement and feature negotiation.
#[cfg(feature = "ap2")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AirPlayMode {
    /// Classic AirPlay 1: ALAC/AAC over RTP, RSA encryption, NTP timing.
    AirPlay1,
    /// AirPlay 2: buffered audio, ChaCha20 encryption, SRP pairing, PTP timing.
    #[default]
    AirPlay2,
}

/// Audio codec type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodec {
    /// Decoded PCM (f32 interleaved). Always delivered regardless of AP1/AP2.
    Pcm,
}

/// AirPlay 1 wire codec advertised in the `_raop._tcp` `cn` TXT record.
///
/// The receiver auto-detects the actual codec per connection from the SDP
/// `rtpmap`; this only controls what is *advertised*. When several are
/// advertised, their order is preserved because sender selection policies vary.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ap1Codec {
    /// Raw linear PCM / `L16` (`cn=0`).
    Pcm,
    /// Apple Lossless (`cn=1`).
    Alac,
}

impl Ap1Codec {
    /// The `cn` TXT record digit for this codec.
    pub(crate) const fn txt_value(self) -> &'static str {
        match self {
            Ap1Codec::Pcm => "0",
            Ap1Codec::Alac => "1",
        }
    }
}

/// AirPlay 1 encryption / authentication mode advertised in the `et` TXT record.
///
/// The receiver auto-dispatches on what a sender actually negotiates (RSA
/// `rsaaeskey`, FairPlay `fpaeskey`, or no key at all); this only controls what
/// is *advertised*. Sender preference rules vary, so advertise only modes the
/// deployment intends to accept.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ap1Encryption {
    /// No encryption (`et=0`). Audio passes through undecrypted.
    None,
    /// RSA session-key exchange (`et=1`, `a=rsaaeskey`).
    Rsa,
    /// FairPlay DRM (`et=3`, `POST /fp-setup` + `a=fpaeskey`).
    FairPlay,
}

impl Ap1Encryption {
    /// The `et` TXT record digit for this mode.
    pub(crate) const fn txt_value(self) -> &'static str {
        match self {
            Ap1Encryption::None => "0",
            Ap1Encryption::Rsa => "1",
            Ap1Encryption::FairPlay => "3",
        }
    }
}

/// Audio format descriptor passed to [`AudioHandler::audio_init`].
#[derive(Debug, Clone, Copy)]
pub struct AudioFormat {
    /// Audio codec (always PCM for decoded output).
    pub codec: AudioCodec,
    /// Bits per sample (always 32 — samples are delivered as `&[f32]`).
    pub bits: u8,
    /// Number of channels.
    pub channels: u8,
    /// Sample rate in Hz.
    pub sample_rate: u32,
}

/// Trait for receiving AirPlay events and creating audio sessions.
///
/// `AudioHandler` is `Send + Sync` — all callbacks can be called from any thread
/// without blocking audio delivery. Metadata, volume, and artwork callbacks are
/// called directly from the RTSP handler thread, never from the audio path.
///
/// A new [`AudioSession`] is created for each audio stream via
/// [`audio_init`](AudioHandler::audio_init). The session only receives PCM samples.
pub trait AudioHandler: Send + Sync + 'static {
    /// Called when a new audio stream starts. Return a session to receive PCM data.
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession>;

    // --- Metadata events (called from RTSP thread, never blocks audio) ---

    /// Volume change in dB (0.0 = max, -144.0 = mute).
    fn on_volume(&self, _volume: f32) {}
    /// Track metadata (parsed from DMAP).
    fn on_metadata(&self, _metadata: &crate::proto::dmap::TrackMetadata) {}
    /// Album artwork (JPEG or PNG).
    fn on_coverart(&self, _coverart: &[u8]) {}
    /// Playback progress (start, current, end in RTP timestamps at 44100 Hz).
    fn on_progress(&self, _start: u32, _current: u32, _end: u32) {}
    /// A remote control interface is available (AP1 DACP).
    ///
    /// With DACP discovery enabled (the default, see
    /// [`RaopServerBuilder::dacp_discovery`](crate::RaopServerBuilder::dacp_discovery))
    /// this is called from a background thread once the sender's `_dacp._tcp`
    /// service has been looked up (up to ~2 s after SETUP).
    fn on_remote_control(&self, _remote: Arc<dyn RemoteControl>) {}
    /// The sender offered DACP remote control (AP1 `SETUP` carried `DACP-ID`
    /// and `Active-Remote`). Called inline and cheaply, before any discovery,
    /// so applications can run their own DACP client.
    fn on_dacp_info(&self, _info: &DacpInfo) {}

    // --- Connection lifecycle ---

    /// Called when a client connects.
    fn on_client_connected(&self, _addr: &str) {}
    /// Called when a client disconnects.
    fn on_client_disconnected(&self, _addr: &str) {}
    /// Called when the library hits a runtime error on a connection — e.g. a
    /// pairing/pair-verify failure, a FairPlay or session-key decrypt failure, a
    /// rejected stream format, or an audio-decoder init failure. Fired at most
    /// once per failure (never per audio packet). Default: log at warn level.
    fn on_error(&self, error: &crate::error::ShairplayError) {
        tracing::warn!(%error, "AirPlay error");
    }
}

/// Storage for paired device keys. Implement this to persist pairing across restarts.
///
/// Without persistence, iPhones that previously paired will send encrypted data
/// on connect and fail because the server has no cached keys.
#[cfg(feature = "ap2")]
pub trait PairingStore: Send + Sync + 'static {
    /// Look up a paired device's Ed25519 public key by device ID.
    fn get(&self, device_id: &str) -> Option<[u8; 32]>;
    /// Save a paired device's Ed25519 public key.
    fn put(&self, device_id: &str, public_key: [u8; 32]);
    /// Remove a paired device.
    fn remove(&self, device_id: &str);

    /// Returns `true` once at least one controller is paired.
    ///
    /// Used to advertise `OneTimePairingRequired` (statusFlags bit 9) only until
    /// the first successful pairing, so already-paired controllers reconnect via
    /// pair-verify instead of being nudged back into setup. The default returns
    /// `false` (always advertise setup-required when a PIN is configured); the
    /// built-in [`MemoryPairingStore`] overrides it, and persistent stores should
    /// too.
    fn has_any_pairing(&self) -> bool {
        false
    }

    /// Load the accessory's persistent Ed25519 **identity** seed, if one was saved.
    ///
    /// This is the server's *own* long-term secret (distinct from the paired peer
    /// keys handled by [`get`](Self::get)/[`put`](Self::put)). Returning `Some`
    /// keeps the accessory's identity — and therefore its advertised `pk` — stable
    /// across restarts so already-paired devices don't need to re-pair.
    ///
    /// The default returns `None`: the server then generates a fresh random
    /// identity on each start and offers it to [`save_identity`](Self::save_identity).
    /// Implement both methods to persist the identity. (To reproduce the legacy
    /// insecure behaviour, return the zero-padded device id as the seed.)
    fn load_identity(&self) -> Option<[u8; 32]> {
        None
    }

    /// Persist the accessory's Ed25519 identity seed generated at startup.
    ///
    /// The default is a no-op (identity is not persisted). Implement together with
    /// [`load_identity`](Self::load_identity) to keep a stable identity.
    fn save_identity(&self, _seed: [u8; 32]) {}
}

/// In-memory pairing store (lost on restart). Use for testing or wrap with file I/O.
#[cfg(feature = "ap2")]
#[derive(Default)]
pub struct MemoryPairingStore {
    keys: std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>>,
}

#[cfg(feature = "ap2")]
impl PairingStore for MemoryPairingStore {
    fn get(&self, device_id: &str) -> Option<[u8; 32]> {
        self.keys.lock().ok()?.get(device_id).copied()
    }
    fn put(&self, device_id: &str, public_key: [u8; 32]) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.insert(device_id.to_string(), public_key);
        }
    }
    fn has_any_pairing(&self) -> bool {
        self.keys.lock().map(|k| !k.is_empty()).unwrap_or(false)
    }
    fn remove(&self, device_id: &str) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.remove(device_id);
        }
    }
}

/// Per-connection audio session — hot path only.
///
/// Created by [`AudioHandler::audio_init`]. Dropped when the client disconnects.
/// Only receives decoded PCM samples and flush events. All metadata, volume,
/// and artwork events go to [`AudioHandler`] instead.
pub trait AudioSession: Send + Sync {
    /// Receive decoded f32 interleaved PCM audio samples.
    fn audio_process(&mut self, samples: &[f32]);
    /// Flush the audio buffer (e.g. on seek).
    fn audio_flush(&mut self) {}
    /// Like [`audio_process`](Self::audio_process), plus the RTP timing of
    /// the packet. Implement this to schedule playout by timestamp (AP1).
    ///
    /// The default forwards to `audio_process`. When the server resamples
    /// (`output_sample_rate`), `timing` still describes the *source* packet.
    fn audio_process_timed(&mut self, samples: &[f32], timing: FrameTiming) {
        let _ = timing;
        self.audio_process(samples);
    }
    /// A sender SYNC packet mapped the RTP timeline onto the local clock (AP1,
    /// about once per second while streaming).
    fn on_playout_anchor(&mut self, _anchor: PlayoutAnchor) {}
}

/// RTP timing of one decoded packet, passed to [`AudioSession::audio_process_timed`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameTiming {
    /// RTP timestamp of the first frame, in source sample-rate units.
    pub rtp_ts: u32,
    /// RTP sequence number.
    pub seq: u16,
    /// The packet was lost and replaced by silence; `rtp_ts` is extrapolated.
    pub silence: bool,
}

/// How a sender time was mapped onto the local clock.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockSource {
    /// NTP exchange with the sender (offset and round trip of the best sample).
    Ntp {
        /// `sender_clock - local_clock`.
        offset: std::time::Duration,
        /// Whether the sender clock is behind ours (offset is negative).
        sender_behind: bool,
        /// Round trip of the sample the offset came from.
        rtt: std::time::Duration,
    },
    /// No NTP estimate yet: the SYNC packet's arrival time stands in for the
    /// sender's "now" (off by the one-way network delay).
    Arrival,
}

/// "Frame `rtp_ts` must be audible at `play_at`": one AP1 SYNC packet mapped
/// onto the local clock. Passed to [`AudioSession::on_playout_anchor`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlayoutAnchor {
    /// RTP timestamp (source sample-rate units).
    pub rtp_ts: u32,
    /// Local time at which `rtp_ts` should be heard.
    pub play_at: std::time::Instant,
    /// Sender-requested latency in frames (e.g. 88200 = 2 s at 44.1 kHz).
    pub latency_frames: u32,
    /// First SYNC after RECORD or FLUSH (RTP extension bit set).
    pub first: bool,
    /// How the sender's clock was mapped.
    pub clock: ClockSource,
}

/// DACP parameters of an AP1 sender, passed to [`AudioHandler::on_dacp_info`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DacpInfo {
    /// `DACP-ID` header; the sender advertises `iTunes_Ctrl_<DACP-ID>._dacp._tcp`.
    pub dacp_id: String,
    /// `Active-Remote` header; must be sent back with every DACP request.
    pub active_remote: String,
    /// RTSP peer address (keeps the IPv6 scope id for link-local peers).
    pub peer: std::net::SocketAddr,
    /// `User-Agent` header, if present (e.g. `AirPlay/960.13.1`).
    pub user_agent: Option<String>,
}

/// Playback command to send to the source device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteCommand {
    /// Start playback.
    Play,
    /// Pause playback.
    Pause,
    /// Skip to next track.
    NextTrack,
    /// Skip to previous track.
    PreviousTrack,
    /// Set volume (0-100).
    SetVolume(u8),
    /// Toggle shuffle mode.
    ToggleShuffle,
    /// Toggle repeat mode.
    ToggleRepeat,
    /// Stop playback.
    Stop,
}

/// Unified remote control interface for AP1 (DACP) and AP2 (MediaRemote).
pub trait RemoteControl: Send + Sync {
    /// Send a playback command to the source device.
    fn send_command(&self, cmd: RemoteCommand) -> Result<(), crate::error::ShairplayError>;
    /// Commands the source device supports. AP1 returns all; AP2 returns advertised set.
    fn available_commands(&self) -> Vec<RemoteCommand>;
}
