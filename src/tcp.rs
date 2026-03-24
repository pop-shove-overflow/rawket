/// Full TCP state machine: RFC 793 + SACK (RFC 2018) + RACK-TLP (RFC 8985) + BBRv3.
use alloc::{vec, vec::Vec};
use core::fmt;
use core::net::{Ipv4Addr, SocketAddrV4};
use crate::{
    eth::{EthHdr, EtherType},
    interface::Interface,
    ip::{
        checksum_add, checksum_finish, pseudo_header_acc, IpProto, Ipv4Hdr,
    },
    timers::{Clock, Deadline},

    Error, Result,
};

pub const HDR_LEN: usize = 20;

/// RFC 6298 §2: clock granularity G used in RTO = SRTT + max(G, 4*RTTVAR).
pub const CLOCK_GRANULARITY_NS: u64 = 1_000_000; // 1 ms

/// RFC 8985 §7.2: worst-case delayed-ACK timer used in TLP PTO calculation.
pub const WC_DEL_ACK_NS: u64 = 25_000_000; // 25 ms

/// RFC 5961 §5: max challenge ACKs per second window.
pub const CHALLENGE_ACK_LIMIT: u8 = 10;

/// TCP control flags bitmask.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct TcpFlags(u8);

impl TcpFlags {
    pub const NONE: Self = Self(0x00);
    pub const FIN:  Self = Self(0x01);
    pub const SYN:  Self = Self(0x02);
    pub const RST:  Self = Self(0x04);
    pub const PSH:  Self = Self(0x08);
    pub const ACK:  Self = Self(0x10);
    /// ECN-Echo: receiver signals Congestion Experienced to the sender.
    pub const ECE:  Self = Self(0x40);
    /// Congestion Window Reduced: sender acknowledges the ECE signal.
    pub const CWR:  Self = Self(0x80);

    #[inline] pub fn has(self, f: Self) -> bool  { self.0 & f.0 != 0 }
    #[inline] pub fn is_empty(self) -> bool      { self.0 == 0 }
    #[inline] pub fn bits(self) -> u8            { self.0 }
    #[inline] pub fn from_bits(b: u8) -> Self    { Self(b) }
}

impl core::ops::BitOr for TcpFlags {
    type Output = Self;
    fn bitor(self, r: Self) -> Self { Self(self.0 | r.0) }
}
impl core::ops::BitOrAssign for TcpFlags {
    fn bitor_assign(&mut self, r: Self) { self.0 |= r.0; }
}
impl core::ops::BitAnd for TcpFlags {
    type Output = Self;
    fn bitand(self, r: Self) -> Self { Self(self.0 & r.0) }
}

/// A fixed-point multiplier with configurable scale.
///
/// `ScaledFloat::new(125)` represents 1.25 (×100 default).
/// `ScaledFloat::x1000(347)` represents 0.347 (×1000 for higher precision).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ScaledFloat { val: u32, scale: u32 }

impl ScaledFloat {
    /// ×100 precision (default). `new(125)` = 1.25.
    pub const fn new(x100: u32) -> Self { Self { val: x100, scale: 100 } }
    /// ×1000 precision. `x1000(347)` = 0.347.
    pub const fn x1000(x1000: u32) -> Self { Self { val: x1000, scale: 1000 } }
    /// Returns `v × self.val / self.scale`.
    #[inline]
    pub fn apply(self, v: u64) -> u64 { v * self.val as u64 / self.scale as u64 }
}

/// A TCP sequence or acknowledgment number with RFC 793 wrapping arithmetic.
///
/// All addition and subtraction wraps modulo 2³².
/// `SeqNum - SeqNum` returns the wrapping distance as `u32`.
/// Ordering must use the `seq_lt` / `seq_le` / `seq_gt` / `seq_ge` helpers —
/// do **not** compare with `<` / `>` directly.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SeqNum(u32);

impl SeqNum {
    pub const fn new(n: u32) -> Self { Self(n) }
    pub fn as_u32(self) -> u32 { self.0 }
}

impl core::ops::Add<u32> for SeqNum {
    type Output = SeqNum;
    fn add(self, n: u32) -> SeqNum { SeqNum(self.0.wrapping_add(n)) }
}
impl core::ops::AddAssign<u32> for SeqNum {
    fn add_assign(&mut self, n: u32) { self.0 = self.0.wrapping_add(n); }
}
impl core::ops::Sub<u32> for SeqNum {
    type Output = SeqNum;
    fn sub(self, n: u32) -> SeqNum { SeqNum(self.0.wrapping_sub(n)) }
}
/// Wrapping distance: `a - b` = how many bytes ahead `a` is of `b`.
impl core::ops::Sub<SeqNum> for SeqNum {
    type Output = u32;
    fn sub(self, rhs: SeqNum) -> u32 { self.0.wrapping_sub(rhs.0) }
}

/// Maximum receive buffer we are willing to hold.  The receive-window
/// advertisement (scaled by `LOCAL_WS_SHIFT`) is derived from remaining
/// space here, so the peer naturally stops sending when the buffer is full.
/// Applications that never call `recv()` will see the window close to zero —
/// this is correct flow-control behaviour, not a memory leak.
/// Window scale lets us advertise up to 1 MiB (16 × 65535) to the peer.
/// Window scale shift we advertise (RFC 1323 §2).  With shift=4 one window
/// unit represents 16 bytes, giving a max window of 16 × 65535 ≈ 1 MiB.
const LOCAL_WS_SHIFT: u8 = 4;


// ── TcpError ──────────────────────────────────────────────────────────────────

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpError {
    Reset   = 1,
    Timeout = 2,
}

impl fmt::Display for TcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self { TcpError::Reset => "RESET", TcpError::Timeout => "TIMEOUT" })
    }
}

// ── TcpConfig ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct TcpConfig {
    pub mss:                       u16,
    pub initial_cwnd_pkts:         u32,
    pub rto_min_ms:                u64,
    pub rto_max_ms:                u64,
    pub max_retransmits:           u8,
    pub bbr_bw_filter_rounds:      u8,
    pub bbr_probe_rtt_duration_ms: u64,
    pub bbr_probe_rtt_interval_ms: u64,
    /// TCP keep-alive idle time in ms (0 = disabled).
    pub keepalive_idle_ms:         u64,
    /// Interval between keep-alive probes in ms.
    pub keepalive_interval_ms:     u64,
    /// Number of unanswered probes before reporting Timeout.
    pub keepalive_count:           u8,
    /// Maximum bytes that may be buffered in the send buffer.  Calls to
    /// [`TcpSocket::send`] that would exceed this limit return
    /// [`Error::WouldBlock`].  Default: 1 MiB.
    pub send_buf_max:              usize,
    /// Maximum bytes that may be buffered in the receive buffer.  Incoming
    /// segments that would exceed this limit are silently dropped (ACK for
    /// rcv_nxt is still sent).  Also drives rcv_wnd advertisement.
    /// Default: 1 MiB.
    pub recv_buf_max:              usize,
    /// Maximum out-of-order segments buffered per connection before
    /// discarding.  SACK blocks are emitted for at most 4 OOO segments
    /// regardless of this value.  Default: 8.
    pub rx_ooo_max:                usize,
    /// TIME_WAIT linger duration in ms (2×MSL).  Default: 120_000 (2 min).
    /// Set to a small value (e.g. 100) in test configs to avoid 120 s waits.
    pub time_wait_ms:              u64,
}

impl Default for TcpConfig {
    fn default() -> Self {
        TcpConfig {
            mss:                       1460,
            initial_cwnd_pkts:         10,
            rto_min_ms:                200,
            rto_max_ms:                60_000,
            max_retransmits:           15,
            bbr_bw_filter_rounds:      10,
            bbr_probe_rtt_duration_ms: 200,
            bbr_probe_rtt_interval_ms: 5_000,
            keepalive_idle_ms:         0,
            keepalive_interval_ms:     75_000,
            keepalive_count:           9,
            send_buf_max:              1 << 20, // 1 MiB
            recv_buf_max:              1 << 20, // 1 MiB
            rx_ooo_max:                8,
            time_wait_ms:              120_000,
        }
    }
}

impl TcpConfig {
    /// Set minimum RTO in milliseconds (default: 200).
    pub fn rto_min_ms(mut self, ms: u64) -> Self { self.rto_min_ms = ms; self }

    /// Set maximum RTO in milliseconds (default: 60_000).
    pub fn rto_max_ms(mut self, ms: u64) -> Self { self.rto_max_ms = ms; self }

    /// Set maximum retransmit attempts (default: 15).
    pub fn max_retransmits(mut self, n: u8) -> Self { self.max_retransmits = n; self }

    /// Set TIME_WAIT linger duration in milliseconds (default: 120_000).
    pub fn time_wait_ms(mut self, ms: u64) -> Self { self.time_wait_ms = ms; self }

    /// Set keep-alive idle time in milliseconds (default: 0 = disabled).
    pub fn keepalive_idle_ms(mut self, ms: u64) -> Self { self.keepalive_idle_ms = ms; self }

    /// Set interval between keep-alive probes in milliseconds (default: 75_000).
    pub fn keepalive_interval_ms(mut self, ms: u64) -> Self { self.keepalive_interval_ms = ms; self }

    /// Set number of unanswered keep-alive probes before timeout (default: 9).
    pub fn keepalive_count(mut self, n: u8) -> Self { self.keepalive_count = n; self }

    /// Set maximum send buffer size in bytes (default: 1 MiB).
    pub fn send_buf_max(mut self, n: usize) -> Self { self.send_buf_max = n; self }

    /// Set maximum out-of-order segments buffered (default: 8).
    pub fn rx_ooo_max(mut self, n: usize) -> Self { self.rx_ooo_max = n; self }

    /// Set MSS in bytes (default: 1460).
    pub fn mss(mut self, n: u16) -> Self { self.mss = n; self }

    /// Set initial congestion window in packets (default: 10).
    pub fn initial_cwnd_pkts(mut self, n: u32) -> Self { self.initial_cwnd_pkts = n; self }
}

// ── State machine ─────────────────────────────────────────────────────────────

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Closed      = 0,
    Listen      = 1,
    SynSent     = 2,
    SynReceived = 3,
    Established = 4,
    FinWait1    = 5,
    FinWait2    = 6,
    CloseWait   = 7,
    Closing     = 8,
    LastAck     = 9,
    TimeWait    = 10,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            State::Closed       => "CLOSED",
            State::Listen       => "LISTEN",
            State::SynSent      => "SYN_SENT",
            State::SynReceived  => "SYN_RECEIVED",
            State::Established  => "ESTABLISHED",
            State::FinWait1     => "FIN_WAIT_1",
            State::FinWait2     => "FIN_WAIT_2",
            State::CloseWait    => "CLOSE_WAIT",
            State::Closing      => "CLOSING",
            State::LastAck      => "LAST_ACK",
            State::TimeWait     => "TIME_WAIT",
        })
    }
}

// ── TcpHdr ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct TcpHdr {
    pub src_port:    u16,
    pub dst_port:    u16,
    pub seq:         SeqNum,
    pub ack:         SeqNum,
    pub data_offset: u8,
    pub flags:       TcpFlags,
    pub window:      u16,
    pub checksum:    u16,
    pub urgent:      u16,
}

impl TcpHdr {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HDR_LEN {
            return Err(Error::InvalidData);
        }
        Ok(TcpHdr {
            src_port:    u16::from_be_bytes([buf[0], buf[1]]),
            dst_port:    u16::from_be_bytes([buf[2], buf[3]]),
            seq:         SeqNum(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]])),
            ack:         SeqNum(u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]])),
            data_offset: buf[12] >> 4,
            flags:       TcpFlags(buf[13]),
            window:      u16::from_be_bytes([buf[14], buf[15]]),
            checksum:    u16::from_be_bytes([buf[16], buf[17]]),
            urgent:      u16::from_be_bytes([buf[18], buf[19]]),
        })
    }

    pub fn emit(
        &self,
        buf: &mut [u8],
        src_ip: &Ipv4Addr,
        dst_ip: &Ipv4Addr,
        payload: &[u8],
    ) -> Result<()> {
        if buf.len() < HDR_LEN {
            return Err(Error::InvalidInput);
        }
        buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buf[4..8].copy_from_slice(&self.seq.as_u32().to_be_bytes());
        buf[8..12].copy_from_slice(&self.ack.as_u32().to_be_bytes());
        buf[12] = self.data_offset << 4;
        buf[13] = self.flags.0;
        buf[14..16].copy_from_slice(&self.window.to_be_bytes());
        buf[16..18].copy_from_slice(&[0, 0]);
        buf[18..20].copy_from_slice(&self.urgent.to_be_bytes());

        let seg_len = (HDR_LEN + payload.len()) as u16;
        let acc = pseudo_header_acc(src_ip, dst_ip, IpProto::TCP, seg_len);
        let acc = checksum_add(acc, &buf[..HDR_LEN]);
        let acc = checksum_add(acc, payload);
        let csum = checksum_finish(acc);
        buf[16..18].copy_from_slice(&csum.to_be_bytes());
        Ok(())
    }

    pub fn hdr_len(&self) -> usize {
        self.data_offset as usize * 4
    }

    pub fn has_flag(&self, f: TcpFlags) -> bool {
        self.flags.has(f)
    }
}

// ── TcpPacket ─────────────────────────────────────────────────────────────────

/// Parsed addresses and payload delivered to a [`TcpSocket`] callback.
///
/// Valid only for the duration of the callback invocation.  An empty `pdu`
/// signals a FIN (EOF) from the peer.
pub struct TcpPacket<'a> {
    pub src:     SocketAddrV4,
    pub dst:     SocketAddrV4,
    /// Layer-4 payload.  Empty on FIN.
    pub pdu: &'a [u8],
}

// ── Retransmit buffer ─────────────────────────────────────────────────────────

struct TxSegment {
    seq:              SeqNum,
    end_seq:          SeqNum,   // seq + len (SYN/FIN count +1)
    flags:            TcpFlags,
    data:             Vec<u8>,
    first_sent_ns:    u64,
    last_sent_ns:     u64,
    retransmits:      u8,
    sacked:           bool,
    // RFC 9438 §4.1 / draft-cheng-iccrg-delivery-rate-estimation snapshots
    delivered_at_send:      u64, // P.delivered: bbr.delivered when sent
    delivered_time_at_send: u64, // P.delivered_time: bbr.delivered_time when sent
    first_send_time_at_send: u64, // P.first_send_time: bbr.first_send_time when sent
    is_app_limited:         bool, // P.is_app_limited: sender was app-limited when sent
}

// ── Out-of-order receive buffer ───────────────────────────────────────────────

struct RxOooSegment {
    seq:     SeqNum,
    data:    Vec<u8>,
    has_fin: bool,
}

// ── BBRv3 ─────────────────────────────────────────────────────────────────────

/// Aggregated per-ACK signals passed to `bbr_on_ack`.
struct BbrAckState {
    acked_bytes:        u64,
    delivery_rate:      u64,
    is_app_limited:     bool,
    rs_prior_delivered: u64,
    newly_lost:         u64,
    rtt_ns:             Option<u64>,
    now:                u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BbrPhase {
    Startup,
    Drain,
    ProbeBwDown,
    ProbeBwCruise,
    ProbeBwRefill,
    ProbeBwUp,
    ProbeRtt,
}

#[derive(Clone, Copy)]
struct BwSample {
    round: u64,
    bw:    u64, // bytes/sec
}

struct BbrState {
    phase:                BbrPhase,
    // Bandwidth estimation
    max_bw:               u64,           // bytes/sec, windowed max
    bw_shortterm:         u64,           // short-term lower bound (spec: BBR.bw_shortterm)
    bw_samples:           [BwSample; 10],
    bw_sample_idx:        usize,
    // Latest delivery signals (1-round-trip max, spec §5.5)
    bw_latest:            u64,           // max delivery rate this round
    inflight_latest:      u64,           // max delivered bytes this round
    // RTT
    min_rtt_ns:           u64,
    min_rtt_stamp_ns:     u64,
    // Congestion window
    cwnd:                 u32,
    inflight_shortterm:   u32,           // short-term lower bound (spec: BBR.inflight_shortterm)
    inflight_longterm:    u32,           // long-term upper bound (spec: BBR.inflight_longterm)
    // Delivery rate tracking (draft-cheng-iccrg-delivery-rate-estimation)
    delivered:            u64,           // C.delivered: total bytes ACKed
    delivered_time:       u64,           // C.delivered_time: clock time of last delivery event
    first_send_time:      u64,           // C.first_send_time: send time of most recently delivered pkt
    app_limited:          u64,           // C.app_limited: delivered + inflight at app-limit (0 = not)
    // Round counting
    round_count:          u64,
    round_start:          bool,          // true on ACK that advances round
    next_round_delivered: u64,
    // Loss round tracking (spec §5.5)
    loss_round_delivered: u64,           // C.delivered at start of current loss round
    loss_round_start:     bool,          // true when a loss round ends on this ACK
    loss_in_round:        bool,          // any loss detected in this round
    // STARTUP convergence
    filled_pipe:          bool,
    full_bw_at_round:     u64,
    full_bw_cnt:          u8,
    // PROBE_BW cycling
    cycle_stamp_ns:       u64,
    // PROBE_RTT
    probe_rtt_done_ns:    u64,           // 0 = not in PROBE_RTT
    prior_cwnd:           u32,
    last_probe_rtt_ns:    u64,
    // Per-round loss tracking (for Startup exit only)
    loss_bytes_round:     u64,
    acked_bytes_round:    u64,
    loss_events_in_round: u32,           // discontiguous lost ranges this round (spec §5.3.1.3)
    last_loss_end_seq:    u32,           // end_seq of previous lost segment (for range merging)
    // ProbeBW phase management (spec §5.4)
    rounds_since_bw_probe: u32,         // rounds since last DOWN entry (for Reno coexistence)
    bw_probe_wait_ns:      u64,         // CRUISE duration target (random 2-3s)
    #[cfg(feature = "test-internals")]
    history:               Vec<BbrSnapshot>,
}

/// Snapshot of BBR state captured at every phase transition.
/// Only available under `test-internals` for system-test assertions.
#[cfg(feature = "test-internals")]
#[derive(Clone, Debug)]
pub struct BbrSnapshot {
    pub phase:              BbrPhase,
    pub cwnd:               u32,
    pub pacing_rate_bps:    u64,
    pub max_bw:             u64,
    pub bw_shortterm:       u64,
    pub bw_latest:          u64,
    pub inflight_shortterm: u32,
    pub inflight_longterm:  u32,
    pub inflight_latest:    u64,
    pub min_rtt_ns:         u64,
    pub round_count:        u64,
    pub loss_in_round:      bool,
    pub delivered:          u64,
    pub filled_pipe:        bool,
    pub bytes_in_flight:    u32,
    pub prior_cwnd:         u32,
    pub cycle_stamp_ns:     u64,
    pub rounds_since_bw_probe: u32,
    pub bw_probe_wait_ns:   u64,
    pub app_limited:        u64,
    pub loss_bytes_round:   u64,
    pub acked_bytes_round:  u64,
    pub loss_events_in_round: u32,
}

/// Snapshot of all TCP timer deadlines for test inspection.
/// Each field is `Some(remaining_ns)` if the timer is armed, `None` if disarmed.
#[cfg(feature = "test-internals")]
#[derive(Clone, Debug)]
pub struct TcpTimerState {
    pub rto_ns:       Option<u64>,
    pub tlp_ns:       Option<u64>,
    pub keepalive_ns: Option<u64>,
    pub persist_ns:   Option<u64>,
    pub pacing_ns:    Option<u64>,
}

impl BbrState {
    fn new(cfg: &TcpConfig) -> Self {
        let init_cwnd = cfg.initial_cwnd_pkts * cfg.mss as u32;
        BbrState {
            phase:                BbrPhase::Startup,
            max_bw:               0,
            bw_shortterm:         u64::MAX,
            bw_samples:           [BwSample { round: 0, bw: 0 }; 10],
            bw_sample_idx:        0,
            bw_latest:            0,
            inflight_latest:      0,
            min_rtt_ns:           u64::MAX,
            min_rtt_stamp_ns:     0,
            cwnd:                 init_cwnd,
            inflight_shortterm:   u32::MAX,
            inflight_longterm:    u32::MAX,
            delivered:            0,
            delivered_time:       0,
            first_send_time:      0,
            app_limited:          0,
            round_count:          0,
            round_start:          false,
            next_round_delivered: 0,
            loss_round_delivered: 0,
            loss_round_start:     false,
            loss_in_round:        false,
            filled_pipe:          false,
            full_bw_at_round:     0,
            full_bw_cnt:          0,
            cycle_stamp_ns:       0,
            probe_rtt_done_ns:    0,
            prior_cwnd:           init_cwnd,
            last_probe_rtt_ns:    0,
            loss_bytes_round:     0,
            acked_bytes_round:    0,
            loss_events_in_round: 0,
            last_loss_end_seq:    0,
            rounds_since_bw_probe: 0,
            bw_probe_wait_ns:      0,
            #[cfg(feature = "test-internals")]
            history:               Vec::new(),
        }
    }
}

// ── TCP options parsing ───────────────────────────────────────────────────────

struct ParsedOpts {
    mss:            Option<u16>,
    sack_permitted: bool,
    sack_blocks:    [Option<(u32, u32)>; 4],
    sack_count:     u8,
    /// RFC 1323 window scale shift from the peer (only valid on SYN/SYN-ACK).
    ws_shift:       Option<u8>,
    ts_val:         Option<u32>,   // peer's TSval (RFC 7323)
    ts_ecr:         Option<u32>,   // peer's TSecr (RFC 7323)
}

fn parse_opts(tcp_buf: &[u8], data_offset: u8) -> ParsedOpts {
    let hdr_end = (data_offset as usize * 4).min(tcp_buf.len());
    let opts    = if hdr_end > HDR_LEN { &tcp_buf[HDR_LEN..hdr_end] } else { &[] };
    let mut res = ParsedOpts {
        mss:            None,
        sack_permitted: false,
        sack_blocks:    [None; 4],
        sack_count:     0,
        ws_shift:       None,
        ts_val:         None,
        ts_ecr:         None,
    };
    let mut i = 0usize;
    while i < opts.len() {
        match opts[i] {
            0x00 => break,
            0x01 => { i += 1; }
            0x02 => {
                // MSS (RFC 793): kind(1) + len(1) + mss(2) — len must be 4.
                if i + 1 < opts.len() && opts[i + 1] != 4 { break; }
                if i + 3 < opts.len() {
                    res.mss = Some(u16::from_be_bytes([opts[i + 2], opts[i + 3]]));
                }
                i += 4;
            }
            0x03 => {
                // Window Scale (RFC 7323 §2): kind(1) + len(1) + shift(1) — len must be 3.
                if i + 1 < opts.len() && opts[i + 1] != 3 { break; }
                if i + 2 < opts.len() {
                    res.ws_shift = Some(opts[i + 2].min(14)); // cap per RFC 7323 §2.3
                }
                i += 3;
            }
            0x04 => {
                // SACK Permitted (RFC 2018): kind(1) + len(1) — len must be 2.
                if i + 1 < opts.len() && opts[i + 1] != 2 { break; }
                res.sack_permitted = true;
                i += 2;
            }
            0x08 => {
                // Timestamps (RFC 7323 §3): kind(1) + len(1) + TSval(4) + TSecr(4) — len must be 10.
                if i + 1 < opts.len() && opts[i + 1] != 10 { break; }
                if i + 9 < opts.len() {
                    res.ts_val = Some(u32::from_be_bytes(
                        [opts[i+2], opts[i+3], opts[i+4], opts[i+5]]));
                    res.ts_ecr = Some(u32::from_be_bytes(
                        [opts[i+6], opts[i+7], opts[i+8], opts[i+9]]));
                }
                i += 10;
            }
            0x05 => {
                if i + 1 >= opts.len() { break; }
                let len = opts[i + 1] as usize;
                if len < 2 { break; }
                let n = (len - 2) / 8;
                let mut j = i + 2;
                for k in 0..n {
                    if j + 8 > opts.len() { break; }
                    let l = u32::from_be_bytes([opts[j],     opts[j+1], opts[j+2], opts[j+3]]);
                    let r = u32::from_be_bytes([opts[j+4], opts[j+5], opts[j+6], opts[j+7]]);
                    if k < 4 {
                        res.sack_blocks[k] = Some((l, r));
                        res.sack_count = (k + 1) as u8;
                    }
                    j += 8;
                }
                i += len;
            }
            _ => {
                if i + 1 < opts.len() {
                    let len = opts[i + 1] as usize;
                    i += if len < 2 { 1 } else { len };
                } else {
                    i += 1;
                }
            }
        }
    }
    res
}

// ── Sequence number helpers ───────────────────────────────────────────────────

/// Returns `true` if `a` is strictly before `b` in TCP's circular sequence-number
/// space (RFC 793 §3.3).  Uses signed wrapping subtraction: correct across the
/// 2³²-wrap boundary.
#[inline]
fn seq_lt(a: SeqNum, b: SeqNum) -> bool { ((a - b) as i32) < 0 }

/// Returns `true` if `a` is before or equal to `b` in TCP's circular sequence-number
/// space (RFC 793 §3.3).  Uses signed wrapping subtraction: correct across the
/// 2³²-wrap boundary.
#[inline]
fn seq_le(a: SeqNum, b: SeqNum) -> bool { ((a - b) as i32) <= 0 }

/// Returns `true` if `a` is strictly after `b` in TCP's circular sequence-number
/// space (RFC 793 §3.3).  Implemented as `seq_lt(b, a)`.
#[inline]
fn seq_gt(a: SeqNum, b: SeqNum) -> bool { seq_lt(b, a) }

/// Returns `true` if `a` is after or equal to `b` in TCP's circular sequence-number
/// space (RFC 793 §3.3).  Implemented as `seq_le(b, a)`.
#[inline]
fn seq_ge(a: SeqNum, b: SeqNum) -> bool { seq_le(b, a) }

// ── ISN helper ────────────────────────────────────────────────────────────────

fn random_u32() -> u32 {
    let mut buf = [0u8; 4];
    // Use the getrandom(2) syscall directly.  Unlike opening /dev/urandom,
    // this cannot fail with EBADF regardless of the process's file-descriptor
    // table state.  With flags=0 it blocks only if the kernel entropy pool
    // has never been initialised (i.e. very early boot), which cannot happen
    // in practice when network code is running.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            buf.as_mut_ptr() as *mut libc::c_void,
            4usize,
            0u32,
        )
    };
    if ret == 4 {
        return u32::from_ne_bytes(buf);
    }
    // Extremely unlikely fallback: mix monotonic clock nanoseconds so the
    // result is at least unpredictable within the process lifetime.
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_nsec as u32)
        .wrapping_mul(0x9e3779b9)
        .wrapping_add(ts.tv_sec as u32)
}

// ── TcpSocket ─────────────────────────────────────────────────────────────────

pub struct TcpSocket {
    tx:          crate::IpTxFn,
    clock:       Clock,
    src:         SocketAddrV4,
    dst:         SocketAddrV4,
    pub state:   State,
    snd_nxt:     SeqNum,
    snd_una:     SeqNum,
    rcv_nxt:     SeqNum,
    last_ack_sent: SeqNum, // RFC 7323 §4.3: for ts_recent update gating
    on_recv:     for<'a> fn(TcpPacket<'a>),
    on_error:    fn(TcpError),

    // Send path
    send_buf:    Vec<u8>,
    unacked:     Vec<TxSegment>,
    sack_ok:     bool,
    peer_mss:    u16,
    /// Peer's window scale shift (0 if not negotiated).
    snd_scale:   u8,
    /// Peer's most recently advertised window, raw (before scaling).
    snd_wnd_raw: u16,

    // Receive path — window scaling
    /// Our window scale shift advertised to the peer (LOCAL_WS_SHIFT, or 0 if
    /// the peer didn't include WS in its SYN so we must not scale).
    rcv_scale:   u8,

    // Receive path
    recv_buf:    Vec<u8>,
    rx_ooo:      Vec<RxOooSegment>,
    rx_ooo_last: Option<SeqNum>, // most recently received OOO seq (for SACK ordering)

    // RTT / RTO (RFC 6298)
    srtt_ns:     u64,   // 0 = no sample yet
    rttvar_ns:   u64,
    rto_ns:      u64,

    // RACK (RFC 8985 §7.2)
    rack_end_seq:    SeqNum,
    rack_xmit_ns:    u64,
    rack_rtt_ns:     u64,    // RTT of the most recently delivered segment
    rack_reo_decay_round: u64, // last round at which reo_wnd was decayed
    /// Extra reorder tolerance added to the RACK timer deadline (ns).
    /// Increased on D-SACK detection; decays toward 0 over time.
    rack_reo_wnd_ns: u64,

    // Deadlines (disarmed = Deadline::default())
    // Note: rto_deadline is reused as the TIME_WAIT linger timer when state == TimeWait.
    rto_deadline: Deadline,
    tlp_deadline: Deadline,
    rto_count:    u8,

    // Duplicate ACK counter (fast retransmit)
    dupack_count:    u8,

    // Challenge ACK rate limit (RFC 5961 §5)
    challenge_ack_count:    u8,
    challenge_ack_epoch_ns: u64,

    // TCP Timestamps (RFC 7323)
    ts_enabled:      bool,   // both sides negotiated timestamps
    ts_recent:       u32,    // last TSval received from peer (echoed as TSecr)

    // Window scaling (RFC 7323)
    peer_offered_ws: bool,  // peer included WS option in SYN (for SYN-ACK emission)

    // ECN (RFC 3168)
    ecn_enabled:    bool,   // both sides negotiated ECN at SYN time
    ecn_ce_pending: bool,   // received CE-marked IP; echo ECE in next ACK
    ecn_cwr_needed: bool,   // received ECE in ACK; send CWR on next data seg
    retransmit_in_progress: bool, // RFC 3168 §6.1.5: suppress ECT on retransmits
    fin_pending:    bool,   // close() called with data in send_buf; piggyback FIN

    // Keep-alive
    last_recv_ns:       u64,   // last time we received data or ACK progress
    keepalive_deadline: Deadline,
    keepalive_probes:   u8,    // probes sent since last activity

    // BBRv3
    bbr: BbrState,

    // Zero-window persist
    persist_deadline: Deadline,
    persist_backoff_ns: u64,   // current persist interval in ns (doubles each probe)

    // Software pacing
    pacing_next: Deadline,

    // Config
    cfg: TcpConfig,

    /// Populated when the socket transitions to Closed due to RST or Timeout.
    /// Checked by the FFI wrapper after each `poll()`.
    pub last_error: Option<TcpError>,
}

impl TcpSocket {
    fn new_raw(
        tx:        crate::IpTxFn,
        clock:     Clock,
        src:       SocketAddrV4,
        on_recv:   for<'a> fn(TcpPacket<'a>),
        on_error:  fn(TcpError),
        cfg:       TcpConfig,
    ) -> Self {
        let isn   = SeqNum::new(random_u32());
        let rto   = cfg.rto_min_ms * 1_000_000;
        let bbr   = BbrState::new(&cfg);
        TcpSocket {
            tx,
            clock,
            src,
            dst:             SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            state:           State::Closed,
            snd_nxt:         isn,
            snd_una:         isn,
            rcv_nxt:         SeqNum::new(0),
            last_ack_sent:   SeqNum::new(0),
            on_recv,
            on_error,
            send_buf:        Vec::new(),
            unacked:         Vec::new(),
            sack_ok:         true,    // default true for client SYN; set from SYN in Listen/SynSent
            peer_mss:        cfg.mss,
            snd_scale:       0,
            snd_wnd_raw:     0,
            rcv_scale:       0,
            recv_buf:        Vec::new(),
            rx_ooo:          Vec::new(),
            rx_ooo_last:     None,
            srtt_ns:         0,
            rttvar_ns:       0,
            rto_ns:          rto,
            rack_end_seq:    isn,
            rack_xmit_ns:    0,
            rack_rtt_ns:     0,
            rack_reo_decay_round: 0,
            rto_deadline:       Deadline::default(),
            tlp_deadline:       Deadline::default(),
            rto_count:          0,
            dupack_count:       0,
            challenge_ack_count:    0,
            challenge_ack_epoch_ns: 0,
            rack_reo_wnd_ns:    0,
            ts_enabled:         false,
            ts_recent:          0,
            peer_offered_ws:    true,   // default true for client SYN; set from SYN in Listen
            ecn_enabled:        false,
            ecn_ce_pending:     false,
            ecn_cwr_needed:     false,
            retransmit_in_progress: false,
            fin_pending:        false,
            last_recv_ns:       0,
            keepalive_deadline: Deadline::default(),
            keepalive_probes:   0,
            bbr,
            persist_deadline:   Deadline::default(),
            persist_backoff_ns: 0,
            pacing_next:        Deadline::default(),
            cfg,
            last_error:      None,
        }
    }

    // ── SYN option bytes (MSS + WS + SACK-Permitted + Timestamps, 24 bytes) ──

    fn syn_opts(&self) -> [u8; 24] {
        let mss = self.cfg.mss;
        let [t0, t1, t2, t3] = (self.clock.monotonic_ms() as u32).to_be_bytes();
        // RFC 7323 §3.2: TSecr = 0 on initial SYN (ts_recent is 0);
        // on SYN-ACK, ts_recent holds peer's TSval from the SYN.
        let [e0, e1, e2, e3] = self.ts_recent.to_be_bytes();
        // RFC 7323 §2.2: omit WS in SYN-ACK when peer omitted it in SYN.
        let (ws_kind, ws_len, ws_val, ws_pad) = if self.peer_offered_ws {
            (0x03u8, 0x03u8, LOCAL_WS_SHIFT, 0x01u8)    // WS (3) + NOP pad (1)
        } else {
            (0x01u8, 0x01u8, 0x01u8, 0x01u8)            // 4 NOPs (no WS)
        };
        [
            0x02, 0x04, (mss >> 8) as u8, mss as u8,   // MSS (4)
            ws_kind, ws_len, ws_val, ws_pad,             // WS (3)+NOP or 4 NOPs
            // RFC 2018 §2: only include SACK-Permitted if peer offered it (or initial SYN).
            if self.sack_ok { 0x04 } else { 0x01 },
            if self.sack_ok { 0x02 } else { 0x01 },
            0x01, 0x01,                                   // 2 NOPs (pad)
            0x01, 0x01, 0x08, 0x0a,                      // NOP NOP kind=8 len=10
            t0, t1, t2, t3,                              // TSval = now
            e0, e1, e2, e3,                              // TSecr
        ]
    }

    // ── TCP Timestamps option (NOP NOP kind=8 len=10 TSval TSecr, 12 bytes) ──

    fn ts_opt(&self) -> [u8; 12] {
        let [t0, t1, t2, t3] = (self.clock.monotonic_ms() as u32).to_be_bytes();
        let [e0, e1, e2, e3] = self.ts_recent.to_be_bytes();
        [0x01, 0x01, 0x08, 0x0a, t0, t1, t2, t3, e0, e1, e2, e3]
    }

    // ── SACK option for receiver ────────────────────────────────────────────
    //
    // max_blocks: 4 without timestamps, 3 with timestamps (to fit in 40-byte
    // option space: 12 TS + 2 NOP + 2 SACK hdr + 8*3 = 40).

    /// Returns the number of bytes written into `buf`.
    fn build_sack_opts(&self, buf: &mut [u8; 40], max_blocks: usize) -> usize {
        let n = self.rx_ooo.len().min(max_blocks);
        if n == 0 { return 0; }
        let opt_len = 2 + 8 * n; // SACK kind (1) + len (1) + 8*n
        let total   = 2 + opt_len; // 2 NOPs + kind + len + blocks
        buf[0] = 0x01; // NOP
        buf[1] = 0x01; // NOP
        buf[2] = 0x05; // SACK kind
        buf[3] = opt_len as u8;
        // RFC 2018 §4: most recently received block must be first.
        let last_idx = self.rx_ooo_last
            .and_then(|seq| self.rx_ooo.iter().position(|s| s.seq == seq));
        let mut slot = 0;
        if let Some(idx) = last_idx {
            let ooo = &self.rx_ooo[idx];
            let off = 4;
            buf[off..off + 4].copy_from_slice(&ooo.seq.as_u32().to_be_bytes());
            let right = ooo.seq + ooo.data.len() as u32;
            buf[off + 4..off + 8].copy_from_slice(&right.as_u32().to_be_bytes());
            slot = 1;
        }
        // RFC 2018 §4: remaining blocks "from most recent to least recent".
        // Since OOO is sorted by seq and segments generally arrive in order,
        // iterate in reverse to report the highest (most recent) ranges first.
        // This maximises the sender's rack_end_seq advancement.
        for i in (0..self.rx_ooo.len()).rev() {
            if slot >= max_blocks { break; }
            if Some(i) == last_idx { continue; }
            let ooo = &self.rx_ooo[i];
            let off = 4 + slot * 8;
            buf[off..off + 4].copy_from_slice(&ooo.seq.as_u32().to_be_bytes());
            let right = ooo.seq + ooo.data.len() as u32;
            buf[off + 4..off + 8].copy_from_slice(&right.as_u32().to_be_bytes());
            slot += 1;
        }
        total
    }

    /// Build a D-SACK option per RFC 2883 §3.
    /// First block is the duplicate range; remaining blocks are OOO ranges.
    /// max_blocks: total SACK blocks (including the D-SACK block itself).
    fn build_dsack_opts(&self, buf: &mut [u8; 40], left: SeqNum, right: SeqNum, max_blocks: usize) -> usize {
        let ooo_n   = self.rx_ooo.len().min(max_blocks - 1);
        let n       = 1 + ooo_n;
        let opt_len = 2 + 8 * n;
        let total   = 2 + opt_len;
        buf[0] = 0x01; buf[1] = 0x01; // NOPs
        buf[2] = 0x05; buf[3] = opt_len as u8;
        buf[4..8].copy_from_slice(&left.as_u32().to_be_bytes());
        buf[8..12].copy_from_slice(&right.as_u32().to_be_bytes());
        for (i, ooo) in self.rx_ooo.iter().take(max_blocks - 1).enumerate() {
            let off = 12 + i * 8;
            buf[off..off + 4].copy_from_slice(&ooo.seq.as_u32().to_be_bytes());
            let r = ooo.seq + ooo.data.len() as u32;
            buf[off + 4..off + 8].copy_from_slice(&r.as_u32().to_be_bytes());
        }
        total
    }

    /// Send an ACK with optional TS and SACK/D-SACK options combined.
    /// RFC 7323 §3.2: TS MUST be included on every non-RST segment.
    fn send_ack_with_opts(&mut self, opts: &[u8]) -> Result<()> {
        if self.ts_enabled {
            let ts = self.ts_opt();
            let mut buf = [0u8; 52]; // 12 TS + 40 SACK max
            buf[..12].copy_from_slice(&ts);
            buf[12..12 + opts.len()].copy_from_slice(opts);
            let seq = self.snd_nxt;
            self.send_segment(seq, TcpFlags::ACK, &[], &buf[..12 + opts.len()])
        } else if !opts.is_empty() {
            let seq = self.snd_nxt;
            self.send_segment(seq, TcpFlags::ACK, &[], opts)
        } else {
            self.send_ctrl_opts(TcpFlags::ACK, &[])
        }
    }

    /// Max SACK blocks that fit in option space, accounting for timestamps.
    fn max_sack_blocks(&self) -> usize { if self.ts_enabled { 3 } else { 4 } }

    /// RFC 8985 §7.2: PTO = 2 * SRTT; += max_ack_delay when FlightSize == 1.
    fn tlp_deadline_ns(&self) -> u64 {
        let mut pto = 2 * self.srtt_ns;
        if self.unacked.len() == 1 {
            pto += WC_DEL_ACK_NS;
        }
        pto
    }

    // ── Frame builder / sender ───────────────────────────────────────────────

    /// Send a TCP segment with explicit sequence number, flags, payload and options.
    /// `opts` must be pre-padded to a multiple of 4 bytes.
    fn send_segment(&mut self, seq: SeqNum, mut flags: TcpFlags, payload: &[u8], opts: &[u8]) -> Result<()> {
        debug_assert!(opts.len().is_multiple_of(4));

        // RFC 1191 §6.4: clamp payload to effective MSS.  PMTUD may have
        // reduced peer_mss since the segment was originally sent.  SYN
        // segments are excluded (no data, option-only).
        let payload = if !flags.has(TcpFlags::SYN) && !payload.is_empty() {
            let ts_overhead = if self.ts_enabled { 12 } else { 0 };
            let eff_mss = (self.peer_mss as usize).saturating_sub(ts_overhead);
            &payload[..payload.len().min(eff_mss)]
        } else {
            payload
        };

        // ECN flag injection (RFC 3168):
        // • ECE on ACK-only segments when we received a CE-marked IP datagram.
        // • CWR on the next data segment after we received an ECE-bearing ACK.
        if self.ecn_enabled {
            if flags.has(TcpFlags::ACK) && !flags.has(TcpFlags::SYN) && self.ecn_ce_pending {
                flags |= TcpFlags::ECE;
                // RFC 3168 §6.1.3: keep ecn_ce_pending=true; cleared only on CWR receipt.
            }
            if !payload.is_empty() && self.ecn_cwr_needed {
                flags |= TcpFlags::CWR;
                self.ecn_cwr_needed = false;
            }
        }

        let tcp_hdr_len = HDR_LEN + opts.len();
        let seg_len     = tcp_hdr_len + payload.len();
        let data_offset = (tcp_hdr_len / 4) as u8;

        let mut buf = alloc::vec![0u8; seg_len];

        buf[0..2].copy_from_slice(&self.src.port().to_be_bytes());
        buf[2..4].copy_from_slice(&self.dst.port().to_be_bytes());
        buf[4..8].copy_from_slice(&seq.as_u32().to_be_bytes());
        buf[8..12].copy_from_slice(&self.rcv_nxt.as_u32().to_be_bytes());
        buf[12] = data_offset << 4;
        buf[13] = flags.0;
        // Advertise how much receive buffer space we have, scaled by rcv_scale.
        // Cap at u16::MAX; if rcv_scale is 0 (not negotiated) this is bytes-exact.
        let recv_headroom = (self.cfg.recv_buf_max as u32).saturating_sub(self.recv_buf.len() as u32);
        let adv_window    = (recv_headroom >> self.rcv_scale).min(u16::MAX as u32) as u16;
        buf[14..16].copy_from_slice(&adv_window.to_be_bytes());
        buf[16..18].copy_from_slice(&[0, 0]); // checksum placeholder
        buf[18..20].copy_from_slice(&[0, 0]); // urgent

        if !opts.is_empty() {
            buf[HDR_LEN..HDR_LEN + opts.len()].copy_from_slice(opts);
        }
        if !payload.is_empty() {
            buf[tcp_hdr_len..].copy_from_slice(payload);
        }

        // Compute TCP checksum over header (including options) + payload.
        let seg_total = seg_len as u16;
        let acc = pseudo_header_acc(self.src.ip(), self.dst.ip(), IpProto::TCP, seg_total);
        let acc = checksum_add(acc, &buf[..seg_len]);
        let csum = checksum_finish(acc);
        buf[16..18].copy_from_slice(&csum.to_be_bytes());

        if flags.has(TcpFlags::ACK) { self.last_ack_sent = self.rcv_nxt; }

        // RFC 3168 §6.1.5: retransmitted packets MUST NOT carry ECT.
        // ECT(0) = 0x02 on original data segments only.
        let dscp_ecn = if self.ecn_enabled && !payload.is_empty() && !self.retransmit_in_progress {
            0x02u8
        } else {
            0u8
        };
        (self.tx)(*self.dst.ip(), IpProto::TCP, dscp_ecn, &buf)
    }

    /// Convenience: control segment using current snd_nxt/rcv_nxt.
    /// Includes TCP Timestamps option when negotiated.
    fn send_ctrl(&mut self, flags: TcpFlags) -> Result<()> {
        if self.ts_enabled {
            let ts = self.ts_opt();
            self.send_ctrl_opts(flags, &ts)
        } else {
            self.send_ctrl_opts(flags, &[])
        }
    }

    /// Challenge ACK with per-second rate limit (RFC 5961 §5).
    fn send_challenge_ack(&mut self) {
        const CHALLENGE_ACK_WINDOW_NS: u64 = 1_000_000_000;
        let now = self.clock.monotonic_ns();
        if now.wrapping_sub(self.challenge_ack_epoch_ns) >= CHALLENGE_ACK_WINDOW_NS {
            self.challenge_ack_count = 0;
            self.challenge_ack_epoch_ns = now;
        }
        if self.challenge_ack_count < CHALLENGE_ACK_LIMIT {
            let _ = self.send_ctrl(TcpFlags::ACK);
            self.challenge_ack_count += 1;
        }
    }

    /// Convenience: control segment with options (e.g. SYN with MSS).
    fn send_ctrl_opts(&mut self, flags: TcpFlags, opts: &[u8]) -> Result<()> {
        let seq = self.snd_nxt;
        self.send_segment(seq, flags, &[], opts)
    }

    // ── BBR helpers ──────────────────────────────────────────────────────────

    /// Returns (pacing_gain_x100, cwnd_gain_x100) per spec §5.6.1 gains table.
    fn bbr_gains(&self) -> (ScaledFloat, ScaledFloat) {
        match self.bbr.phase {
            BbrPhase::Startup      => (ScaledFloat::new(289), ScaledFloat::new(200)),
            BbrPhase::Drain        => (ScaledFloat::x1000(347), ScaledFloat::new(200)),
            BbrPhase::ProbeBwDown  => (ScaledFloat::new(90),  ScaledFloat::new(200)),
            BbrPhase::ProbeBwCruise=> (ScaledFloat::new(100), ScaledFloat::new(200)),
            BbrPhase::ProbeBwRefill=> (ScaledFloat::new(100), ScaledFloat::new(200)),
            BbrPhase::ProbeBwUp    => (ScaledFloat::new(125), ScaledFloat::new(225)),
            BbrPhase::ProbeRtt     => (ScaledFloat::new(100), ScaledFloat::new(50)),
        }
    }

    /// Bytes-per-second pacing rate given current BBR state.
    /// Spec §5.5: BBR.bw = min(BBR.max_bw, BBR.bw_shortterm)
    fn pacing_rate_bps(&self) -> u64 {
        let effective_bw = if self.bbr.bw_shortterm == u64::MAX {
            self.bbr.max_bw
        } else {
            self.bbr.max_bw.min(self.bbr.bw_shortterm)
        };
        if effective_bw == 0 { return 0; }
        let (pacing_gain, _) = self.bbr_gains();
        pacing_gain.apply(effective_bw)
    }

    /// Nanoseconds between MSS-sized sends at current pacing rate.
    fn pacing_interval_ns(&self) -> u64 {
        let rate = self.pacing_rate_bps();
        if rate == 0 { return 0; } // 0 = send immediately
        self.cfg.mss as u64 * 1_000_000_000 / rate
    }

    /// Spec §5.5: BBRIsProbingBW() — true for phases that are probing bandwidth.
    /// Loss adaptation is SKIPPED during these phases.
    pub fn bbr_is_probing_bw(&self) -> bool {
        matches!(self.bbr.phase,
            BbrPhase::Startup | BbrPhase::ProbeBwRefill | BbrPhase::ProbeBwUp)
    }

    /// Update BBR windowed-max bandwidth and cwnd after receiving ACKs.
    ///
    /// Follows the spec ordering from draft-ietf-ccwg-bbr §5.5:
    ///   BBRUpdateModelAndState → BBRUpdateControlParameters
    fn bbr_on_ack(&mut self, s: BbrAckState) {
        if s.acked_bytes == 0 { return; }

        // Delivery accounting — C.delivered updated here (after rate sample).
        self.bbr.delivered         += s.acked_bytes;
        self.bbr.acked_bytes_round += s.acked_bytes;

        // ── BBRUpdateLatestDeliverySignals (spec §5.5) ──────────────────
        // Order: (1) round counting, (2) reset at round start, (3) update.
        self.bbr.loss_round_start = false;
        if self.bbr.delivered >= self.bbr.loss_round_delivered {
            self.bbr.loss_round_delivered = self.bbr.delivered
                + ((self.snd_nxt - self.snd_una) as u64).max(1);
            self.bbr.loss_round_start = true;
        }

        // BBRUpdateRound (spec §5.5): advance when the ACKed packet's
        // delivery snapshot has crossed next_round_delivered.
        self.bbr.round_start = false;
        if s.rs_prior_delivered >= self.bbr.next_round_delivered {
            self.bbr.next_round_delivered = self.bbr.delivered;
            self.bbr.round_count           += 1;
            self.bbr.rounds_since_bw_probe += 1;
            self.bbr.round_start            = true;
            // Per-round acked/loss bytes reset for Startup loss-exit check.
            // loss_events_in_round and last_loss_end_seq are reset in
            // bbr_phase_update (BBRCheckStartupHighLoss) to ensure RACK
            // losses from the current ACK are visible before the reset.
            self.bbr.loss_bytes_round  = 0;
            self.bbr.acked_bytes_round = 0;
        }

        // Spec: reset bw_latest/inflight_latest at round start BEFORE
        // updating with the current sample.
        if self.bbr.round_start {
            self.bbr.bw_latest       = 0;
            self.bbr.inflight_latest = 0;
        }
        self.bbr.bw_latest       = self.bbr.bw_latest.max(s.delivery_rate);
        self.bbr.inflight_latest = self.bbr.inflight_latest.max(s.acked_bytes);

        // ── BBRUpdateMaxBw — windowed max BW per round ──────────────────
        // Spec: skip app-limited samples unless they exceed current BBR.bw.
        let effective_bw = if self.bbr.bw_shortterm == u64::MAX {
            self.bbr.max_bw
        } else {
            self.bbr.max_bw.min(self.bbr.bw_shortterm)
        };
        if s.delivery_rate > 0 && (!s.is_app_limited || s.delivery_rate > effective_bw) {
            let n_rounds  = (self.cfg.bbr_bw_filter_rounds as usize).clamp(1, 10);
            let cur_round = self.bbr.round_count;
            let idx       = self.bbr.bw_sample_idx;
            // One entry per round: update in place or advance to next slot.
            if self.bbr.bw_samples[idx].round == cur_round {
                if s.delivery_rate > self.bbr.bw_samples[idx].bw {
                    self.bbr.bw_samples[idx].bw = s.delivery_rate;
                }
            } else {
                let new_idx = (idx + 1) % n_rounds;
                self.bbr.bw_samples[new_idx] = BwSample { round: cur_round, bw: s.delivery_rate };
                self.bbr.bw_sample_idx = new_idx;
            }
            self.bbr.max_bw = self.bbr.bw_samples[..n_rounds]
                .iter()
                .filter(|bs| bs.bw > 0 && cur_round.saturating_sub(bs.round) < n_rounds as u64)
                .map(|bs| bs.bw)
                .max()
                .unwrap_or(s.delivery_rate)
                .max(s.delivery_rate);
        }

        // ── BBRUpdateCongestionSignals (spec §5.5) ──────────────────────
        if self.bbr.loss_round_start {
            self.bbr_adapt_lower_bounds();
            self.bbr.loss_in_round = false;
        }

        // Min RTT filter
        if let Some(rtt) = s.rtt_ns {
            if rtt < self.bbr.min_rtt_ns {
                self.bbr.min_rtt_ns       = rtt;
                self.bbr.min_rtt_stamp_ns = s.now;
            }
        }

        // ── BBRModulateCwndForRecovery (spec §5.6.2) ───────────────────
        let four_mss = 4 * self.cfg.mss as u32;
        if s.newly_lost > 0 {
            self.bbr.cwnd = self.bbr.cwnd.saturating_sub(s.newly_lost as u32)
                .max(four_mss);
        }

        // ── BBRSetCwnd (spec §5.6.2) ────────────────────────────────────
        if self.bbr.phase == BbrPhase::ProbeRtt {
            self.bbr.cwnd = four_mss;
        } else if !self.bbr.filled_pipe {
            // Startup: cwnd grows uncapped (spec: "if not filled_pipe:
            // cwnd = cwnd + rs.newly_acked").  Only loss-based bounds
            // (via bbr_bound_cwnd_for_model) can reduce it.
            self.bbr.cwnd = self.bbr.cwnd.saturating_add(s.acked_bytes as u32)
                .max(four_mss);
        } else {
            let (_, cwnd_gain) = self.bbr_gains();
            let bdp = if self.bbr.min_rtt_ns < u64::MAX {
                self.bbr.max_bw * self.bbr.min_rtt_ns / 1_000_000_000
            } else {
                self.cfg.mss as u64 * self.cfg.initial_cwnd_pkts as u64
            };
            let max_inflight = cwnd_gain.apply(bdp) as u32 + four_mss;
            let new_cwnd = self.bbr.cwnd.saturating_add(s.acked_bytes as u32);
            self.bbr.cwnd = new_cwnd.min(max_inflight).max(four_mss);
        }

        // ── BBRBoundCwndForModel (spec §5.6.3) ─────────────────────────
        self.bbr_bound_cwnd_for_model();

        // Phase transitions
        self.bbr_phase_update(s.now);

        // ── BBRAdvanceLatestDeliverySignals (spec §5.5) ─────────────────
        // Reset to 0 at end of processing so next round starts fresh.
        if self.bbr.round_start {
            self.bbr.bw_latest       = 0;
            self.bbr.inflight_latest = 0;
        }

        // If the stale pacing deadline is farther in the future than one new
        // pacing interval, disarm it.  The next flush_send_buf call will send
        // a segment immediately and then re-arm with the correct interval.
        if let Some(remaining_ns) = self.pacing_next.remaining_ns(s.now) {
            if remaining_ns > self.pacing_interval_ns() {
                self.pacing_next.disarm();
            }
        }
    }

    /// Spec §5.5: BBRAdaptLowerBoundsFromCongestion — once per round-trip.
    fn bbr_adapt_lower_bounds(&mut self) {
        if self.bbr_is_probing_bw() {
            return; // skip during Startup, ProbeBW_REFILL, ProbeBW_UP
        }
        if self.bbr.loss_in_round {
            self.bbr_init_lower_bounds();
            self.bbr_loss_lower_bounds();
        }
    }

    /// Spec §5.5: BBRInitLowerBounds — initialize from max_bw on first loss.
    fn bbr_init_lower_bounds(&mut self) {
        if self.bbr.bw_shortterm == u64::MAX {
            self.bbr.bw_shortterm = self.bbr.max_bw;
        }
        if self.bbr.inflight_shortterm == u32::MAX {
            self.bbr.inflight_shortterm = self.bbr.cwnd;
        }
    }

    /// Spec §5.5: BBRLossLowerBounds — Beta=0.7 multiplicative decrease.
    fn bbr_loss_lower_bounds(&mut self) {
        // bw_shortterm = max(bw_latest, Beta * bw_shortterm)
        self.bbr.bw_shortterm = self.bbr.bw_latest
            .max(self.bbr.bw_shortterm * 70 / 100);
        // inflight_shortterm = max(inflight_latest, Beta * inflight_shortterm)
        self.bbr.inflight_shortterm = (self.bbr.inflight_latest as u32)
            .max(self.bbr.inflight_shortterm * 70 / 100);
    }

    /// Spec §5.5: BBRResetShortTermModel — called at REFILL entry and ProbeRTT exit.
    fn bbr_reset_short_term_model(&mut self) {
        self.bbr.bw_shortterm       = u64::MAX;
        self.bbr.inflight_shortterm = u32::MAX;
    }

    /// Spec §5.5: BBRResetCongestionSignals.
    fn bbr_reset_congestion_signals(&mut self) {
        self.bbr.loss_in_round   = false;
        self.bbr.bw_latest       = 0;
        self.bbr.inflight_latest = 0;
    }

    /// Spec §5.6.3: BBRBoundCwndForModel — apply inflight bounds to cwnd.
    fn bbr_bound_cwnd_for_model(&mut self) {
        let cap = match self.bbr.phase {
            BbrPhase::ProbeBwDown | BbrPhase::ProbeBwUp | BbrPhase::ProbeBwRefill
            | BbrPhase::Drain =>
                self.bbr.inflight_longterm,
            BbrPhase::ProbeBwCruise | BbrPhase::ProbeRtt => {
                // 0.85 * inflight_longterm (headroom)
                if self.bbr.inflight_longterm == u32::MAX { u32::MAX }
                else { self.bbr.inflight_longterm * 85 / 100 }
            }
            _ => u32::MAX, // Startup: no longterm cap
        };
        // Apply inflight_shortterm (possibly infinite)
        let cap = cap.min(self.bbr.inflight_shortterm);
        let min_pipe_cwnd = 4 * self.cfg.mss as u32;
        let cap = cap.max(min_pipe_cwnd);
        if self.bbr.cwnd > cap {
            self.bbr.cwnd = cap;
        }
    }

    fn bbr_phase_update(&mut self, now: u64) {
        match self.bbr.phase {
            BbrPhase::Startup => {
                // BBRCheckStartupFullBandwidth (spec §5.3.1.2):
                // Only evaluate at round boundaries, per spec:
                //   "if filled_pipe or !round_start: return"
                if !self.bbr.filled_pipe && self.bbr.round_start {
                    let max = self.bbr.max_bw;
                    if max > 0 && max >= ScaledFloat::new(125).apply(self.bbr.full_bw_at_round) {
                        self.bbr.full_bw_at_round = max;
                        self.bbr.full_bw_cnt      = 0;
                    } else {
                        self.bbr.full_bw_cnt += 1;
                        if self.bbr.full_bw_cnt >= 3 {
                            self.bbr.filled_pipe = true;
                        }
                    }
                    // BBRCheckStartupHighLoss (spec §5.3.1.3):
                    // Evaluate accumulated loss_events_in_round BEFORE resetting.
                    // All three must hold:
                    // 1. loss_in_round (at least one loss this round)
                    // 2. loss rate > 2% (BBR.LossThresh)
                    // 3. ≥ 6 discontiguous lost sequence ranges (BBRStartupFullLossCnt)
                    if self.bbr.loss_in_round && self.bbr.acked_bytes_round > 0 {
                        let loss_rate = self.bbr.loss_bytes_round * 100 / self.bbr.acked_bytes_round;
                        if loss_rate > 2 && self.bbr.loss_events_in_round >= 6 {
                            self.bbr.filled_pipe = true;
                            // Set inflight_longterm per spec: max(bdp, inflight_latest)
                            let bdp = self.bbr_bdp() as u32;
                            self.bbr.inflight_longterm = bdp.max(self.bbr.inflight_latest as u32);
                        }
                    }
                    // Reset loss counter for the new round (spec §5.3.1.3)
                    self.bbr.loss_events_in_round = 0;
                    self.bbr.last_loss_end_seq    = 0;
                }
                if self.bbr.filled_pipe {
                    // Record Startup snapshot before transitioning to Drain
                    // so tests can inspect Startup pacing gain via bbr_history().
                    #[cfg(feature = "test-internals")]
                    self.bbr_record_snapshot();
                    self.bbr.phase = BbrPhase::Drain;
                    #[cfg(feature = "test-internals")]
                    self.bbr_record_snapshot();
                }
            }
            BbrPhase::Drain => {
                let bytes_in_flight = (self.snd_nxt - self.snd_una) as u64;
                let bdp = self.bbr_bdp();
                if bytes_in_flight <= bdp.max(1) {
                    self.bbr_enter_probe_bw_down(now);
                }
            }
            BbrPhase::ProbeBwDown => {
                // Spec §5.4: check if probe wait expired (can skip CRUISE).
                if self.bbr_check_probe_rtt(now) { return; }
                if self.bbr_check_time_to_probe_bw(now) { return; }
                // Transition to CRUISE when in-flight ≤ BDP
                let bytes_in_flight = (self.snd_nxt - self.snd_una) as u64;
                let bdp = self.bbr_bdp();
                if bytes_in_flight <= bdp.max(1) {
                    self.bbr.phase = BbrPhase::ProbeBwCruise;
                    #[cfg(feature = "test-internals")]
                    self.bbr_record_snapshot();
                }
            }
            BbrPhase::ProbeBwCruise => {
                if self.bbr_check_probe_rtt(now) { return; }
                // Spec §5.4: time-based or Reno coexistence round-based trigger.
                self.bbr_check_time_to_probe_bw(now);
            }
            BbrPhase::ProbeBwRefill => {
                if self.bbr_check_probe_rtt(now) { return; }
                // Spec §5.4.4: transition to UP at next round boundary.
                if self.bbr.round_start {
                    self.bbr_enter_probe_bw_up(now);
                }
            }
            BbrPhase::ProbeBwUp => {
                if self.bbr_check_probe_rtt(now) { return; }
                // Spec §5.4.4: stay UP until min_rtt elapsed AND inflight > 1.25*BDP.
                let elapsed = now.saturating_sub(self.bbr.cycle_stamp_ns);
                let min_rtt = if self.bbr.min_rtt_ns < u64::MAX {
                    self.bbr.min_rtt_ns
                } else {
                    self.srtt_ns.max(1_000_000)
                };
                let inflight = (self.snd_nxt - self.snd_una) as u64;
                let target = self.bbr_bdp() * 125 / 100; // 1.25 × BDP
                if elapsed >= min_rtt && inflight > target.max(1) {
                    self.bbr_enter_probe_bw_down(now);
                }
            }
            BbrPhase::ProbeRtt => {
                if self.bbr.probe_rtt_done_ns > 0 && now >= self.bbr.probe_rtt_done_ns {
                    self.bbr.probe_rtt_done_ns = 0;
                    // Spec §4.3.4.6 BBRExitProbeRTT: refresh min_rtt_stamp
                    // so the next probe_rtt_interval countdown restarts from
                    // now (the point where we last confirmed min_rtt).
                    self.bbr.min_rtt_stamp_ns  = now;
                    self.bbr.cwnd              = self.bbr.prior_cwnd;
                    // Spec: BBRResetShortTermModel at ProbeRTT exit
                    self.bbr_reset_short_term_model();
                    self.bbr_enter_probe_bw_down(now);
                }
            }
        }
    }

    /// Record a snapshot of full BBR state for test inspection.
    #[cfg(feature = "test-internals")]
    fn bbr_record_snapshot(&mut self) {
        self.bbr.history.push(BbrSnapshot {
            phase:              self.bbr.phase,
            cwnd:               self.bbr.cwnd,
            pacing_rate_bps:    self.pacing_rate_bps(),
            max_bw:             self.bbr.max_bw,
            bw_shortterm:       self.bbr.bw_shortterm,
            bw_latest:          self.bbr.bw_latest,
            inflight_shortterm: self.bbr.inflight_shortterm,
            inflight_longterm:  self.bbr.inflight_longterm,
            inflight_latest:    self.bbr.inflight_latest,
            min_rtt_ns:         self.bbr.min_rtt_ns,
            round_count:        self.bbr.round_count,
            loss_in_round:      self.bbr.loss_in_round,
            delivered:          self.bbr.delivered,
            filled_pipe:        self.bbr.filled_pipe,
            bytes_in_flight:    self.snd_nxt - self.snd_una,
            prior_cwnd:         self.bbr.prior_cwnd,
            cycle_stamp_ns:     self.bbr.cycle_stamp_ns,
            rounds_since_bw_probe: self.bbr.rounds_since_bw_probe,
            bw_probe_wait_ns:   self.bbr.bw_probe_wait_ns,
            app_limited:        self.bbr.app_limited,
            loss_bytes_round:   self.bbr.loss_bytes_round,
            acked_bytes_round:  self.bbr.acked_bytes_round,
            loss_events_in_round: self.bbr.loss_events_in_round,
        });
    }

    /// BDP estimate in bytes.
    fn bbr_bdp(&self) -> u64 {
        if self.bbr.min_rtt_ns < u64::MAX && self.bbr.max_bw > 0 {
            self.bbr.max_bw * self.bbr.min_rtt_ns / 1_000_000_000
        } else { 0 }
    }

    /// Enter ProbeBW_DOWN: start a new ProbeBW cycle.
    /// Calls BBRPickProbeWait to randomize the next probe timing.
    fn bbr_enter_probe_bw_down(&mut self, now: u64) {
        self.bbr_reset_congestion_signals();
        self.bbr.phase           = BbrPhase::ProbeBwDown;
        self.bbr.cycle_stamp_ns  = now;
        // BBRPickProbeWait (spec §5.4.3): randomize CRUISE duration.
        self.bbr.rounds_since_bw_probe = random_u32() & 1; // rand(0, 1)
        // bw_probe_wait = 2s + rand(0..1s)
        self.bbr.bw_probe_wait_ns = 2_000_000_000
            + (random_u32() % 1_000_000) as u64 * 1000; // 0..999_999_000 ns ≈ 0..1s
        #[cfg(feature = "test-internals")]
        self.bbr_record_snapshot();
    }

    /// Enter ProbeBW_REFILL: reset short-term model.
    fn bbr_enter_probe_bw_refill(&mut self) {
        self.bbr_reset_short_term_model();
        self.bbr.phase = BbrPhase::ProbeBwRefill;
        #[cfg(feature = "test-internals")]
        self.bbr_record_snapshot();
    }

    /// Enter ProbeBW_UP: probe for more bandwidth.
    fn bbr_enter_probe_bw_up(&mut self, now: u64) {
        self.bbr.phase           = BbrPhase::ProbeBwUp;
        self.bbr.cycle_stamp_ns  = now;
        #[cfg(feature = "test-internals")]
        self.bbr_record_snapshot();
    }

    /// Spec §5.4: check if it's time to probe BW (CRUISE→REFILL or DOWN→REFILL).
    /// Returns true if we transitioned.
    fn bbr_check_time_to_probe_bw(&mut self, now: u64) -> bool {
        // Time-based trigger: elapsed since DOWN entry >= bw_probe_wait
        let elapsed = now.saturating_sub(self.bbr.cycle_stamp_ns);
        let time_to_probe = self.bbr.bw_probe_wait_ns > 0
            && elapsed >= self.bbr.bw_probe_wait_ns;
        // Round-based trigger: Reno coexistence (spec §5.4.5)
        let reno_rounds = self.bbr_reno_coex_rounds();
        let round_to_probe = self.bbr.rounds_since_bw_probe >= reno_rounds;
        if time_to_probe || round_to_probe {
            self.bbr_enter_probe_bw_refill();
            return true;
        }
        false
    }

    /// Spec §5.4.5: Reno-coexistence probe round target.
    /// Returns the max rounds to stay in CRUISE before probing.
    fn bbr_reno_coex_rounds(&self) -> u32 {
        let bdp = self.bbr_bdp();
        let loss_thresh_mss = (self.cfg.mss as u64) * 2 / 100; // MSS × 2% (BBR.LossThresh)
        if loss_thresh_mss == 0 {
            return 63;
        }
        let rounds = bdp / loss_thresh_mss.max(1);
        (rounds as u32).clamp(2, 63)
    }

    /// Check if it's time to enter ProbeRTT. Returns true if we transitioned.
    fn bbr_check_probe_rtt(&mut self, now: u64) -> bool {
        // Convert ms config values to ns for comparison with ns timestamps.
        let probe_rtt_interval_ns = self.cfg.bbr_probe_rtt_interval_ms * 1_000_000;
        if probe_rtt_interval_ns > 0
            && now.saturating_sub(self.bbr.min_rtt_stamp_ns) > probe_rtt_interval_ns
            && self.bbr.probe_rtt_done_ns == 0
        {
            self.bbr.prior_cwnd        = self.bbr.cwnd;
            self.bbr.cwnd              = 4 * self.cfg.mss as u32;
            self.bbr.probe_rtt_done_ns = now + self.cfg.bbr_probe_rtt_duration_ms * 1_000_000;
            self.bbr.phase             = BbrPhase::ProbeRtt;
            self.bbr.last_probe_rtt_ns = now;
            #[cfg(feature = "test-internals")]
            self.bbr_record_snapshot();
            return true;
        }
        false
    }

    /// Record loss — sets boolean loss_in_round flag (spec §5.5).
    /// `seq`/`end_seq` are used to count discontiguous lost ranges (spec §5.3.1.3).
    fn bbr_on_loss(&mut self, lost_bytes: u64, seq: SeqNum, end_seq: SeqNum) {
        self.bbr.loss_bytes_round += lost_bytes;
        self.bbr.loss_in_round = true;
        // Count discontiguous lost sequence ranges: if this segment is not
        // contiguous with the previous lost segment, it starts a new range.
        let new_range = self.bbr.loss_events_in_round == 0 || seq.0 != self.bbr.last_loss_end_seq;
        if new_range {
            self.bbr.loss_events_in_round += 1;
        }
        self.bbr.last_loss_end_seq = end_seq.0;
    }

    // ── SACK processing (runs on ALL ACKs — advancing and duplicate) ────────

    /// Mark unacked segments covered by SACK blocks and update RACK state.
    fn mark_sack_blocks(&mut self, opts: &ParsedOpts) {
        let now = self.clock.monotonic_ns();
        // RFC 2018 §3: receiver MAY renege on previously SACKed data.
        // Rebuild sacked state from scratch on each ACK so that reneged
        // segments become eligible for retransmission.  This applies even
        // when sack_count == 0: if SACK was negotiated but the ACK carries
        // no SACK blocks, all previously-SACKed segments are reneged.
        for seg in &mut self.unacked {
            seg.sacked = false;
        }
        for k in 0..opts.sack_count as usize {
            if let Some((left, right)) = opts.sack_blocks[k] {
                let (left, right) = (SeqNum::new(left), SeqNum::new(right));
                for seg in &mut self.unacked {
                    if seq_ge(seg.seq, left) && seq_le(seg.end_seq, right) {
                        seg.sacked = true;
                        if seq_gt(seg.end_seq, self.rack_end_seq) {
                            self.rack_end_seq = seg.end_seq;
                            self.rack_xmit_ns = seg.last_sent_ns;
                            self.rack_rtt_ns  = now.saturating_sub(seg.last_sent_ns).max(1);
                        }
                    }
                }
            }
        }
    }

    /// RACK loss detection (RFC 8985 §7.2): retransmit segments that are
    /// past the reorder window relative to the most-recently-SACKed segment.
    ///
    /// Two loss criteria (both from RFC 8985 §7.2):
    ///  1. **Time-based**: `seg.xmit_ts < rack.xmit_ts - reo_wnd`
    ///  2. **Packet-count**: ≥ dup_ack_thresh (3) segments SACKed *after*
    ///     this one  — equivalent to "3 packets have been delivered after
    ///     this one was sent, yet it remains unacknowledged."
    ///
    /// Returns total lost bytes (for BBRModulateCwndForRecovery).
    fn rack_detect_losses(&mut self) -> u64 {
        let now = self.clock.monotonic_ns();
        let rack_rtt = if self.rack_rtt_ns > 0 { self.rack_rtt_ns } else { self.srtt_ns.max(1) };
        let min_rtt  = if self.bbr.min_rtt_ns < u64::MAX { self.bbr.min_rtt_ns } else { rack_rtt };
        let reorder_window = (min_rtt / 4).max(1) + self.rack_reo_wnd_ns;
        let mut retx: Vec<(SeqNum, TcpFlags, Vec<u8>)> = Vec::new();
        for seg in &self.unacked {
            if seg.sacked { continue; }
            if !seq_le(seg.end_seq, self.rack_end_seq) { continue; }
            // Criterion 1: time-based (applies to retransmits too)
            let time_lost = now >= seg.last_sent_ns + rack_rtt + reorder_window;
            // Criterion 2: packet-count (dup_ack_thresh = 3)
            // Only for original transmissions — retransmitted segments use
            // the time-based criterion to avoid re-detecting the same loss.
            let pkt_lost = seg.retransmits == 0 && {
                let sacked_after = self.unacked.iter()
                    .filter(|s| s.sacked && seq_gt(s.seq, seg.end_seq))
                    .count();
                sacked_after >= 3
            };
            if time_lost || pkt_lost {
                retx.push((seg.seq, seg.flags, seg.data.clone()));
            }
        }
        let mut total_lost = 0u64;
        for (seq, flags, data) in retx {
            let now = self.clock.monotonic_ns();
            // Update retransmit state + delivery-rate snapshots (spec: OnPacketSent
            // applies to all sends including retransmits).
            for s in &mut self.unacked {
                if s.seq == seq {
                    s.retransmits += 1;
                    s.last_sent_ns = now;
                    s.first_sent_ns = now;
                    s.delivered_at_send = self.bbr.delivered;
                    s.delivered_time_at_send = self.bbr.delivered_time;
                    s.first_send_time_at_send = self.bbr.first_send_time;
                    s.is_app_limited = self.bbr.app_limited > 0;
                }
            }
            let syn_fin_bytes = if !(flags & (TcpFlags::SYN | TcpFlags::FIN)).is_empty() { 1 } else { 0 };
            let lost_bytes = data.len() as u64 + syn_fin_bytes as u64;
            let end_seq = seq + data.len() as u32 + syn_fin_bytes;
            total_lost += lost_bytes;
            self.bbr_on_loss(lost_bytes, seq, end_seq);
            let opts_arr;
            let ts_arr;
            let opts_slice: &[u8] = if flags.has(TcpFlags::SYN) {
                opts_arr = self.syn_opts();
                &opts_arr
            } else if self.ts_enabled {
                ts_arr = self.ts_opt();
                &ts_arr
            } else {
                &[]
            };
            self.retransmit_in_progress = true;
            let _ = self.send_segment(seq, flags, &data, opts_slice);
            self.retransmit_in_progress = false;
        }
        total_lost
    }

    // ── Core ACK processing ──────────────────────────────────────────────────

    fn on_ack(&mut self, new_ack: SeqNum, opts: &ParsedOpts) {
        let now          = self.clock.monotonic_ns();
        let mut acked_data = 0u64;  // payload bytes (SYN/FIN seq-space excluded; used for BBR)
        let mut rtt_sample: Option<u64> = None;
        // Rate sample state (draft-cheng-iccrg-delivery-rate-estimation §3.3).
        // We track the NEWEST (most recently sent) ACKed packet's snapshot.
        let mut rs_prior_delivered:  u64  = 0;
        let mut rs_prior_time:       u64  = 0;
        let mut rs_send_elapsed:     u64  = 0;
        let mut rs_is_app_limited:   bool = false;
        let mut rs_newest_send_time: u64  = 0;
        let mut rs_newest_end_seq:   SeqNum = SeqNum(0);
        let mut rs_has_data:         bool = false;
        let old_snd_una  = self.snd_una;

        // Only process if ack advances snd_una
        if !seq_gt(new_ack, self.snd_una) { return; }
        self.dupack_count = 0; // belt-and-braces: any advancing ACK resets the counter

        // 1. Remove cumulatively ACKed segments and measure RTT.
        //    Per spec UpdateRateSample: select the newest (most recently sent)
        //    ACKed packet for the delivery-rate snapshot.
        let mut i = 0;
        while i < self.unacked.len() {
            let seg = &self.unacked[i];
            if seq_le(seg.end_seq, new_ack) {
                acked_data += seg.data.len() as u64;
                // Karn's: RTT only from non-retransmitted segments
                if seg.retransmits == 0 && rtt_sample.is_none() {
                    rtt_sample = Some(now.saturating_sub(seg.first_sent_ns));
                }
                // UpdateRateSample: keep newest (most recently sent) packet.
                let is_newer = seg.first_sent_ns > rs_newest_send_time
                    || (seg.first_sent_ns == rs_newest_send_time
                        && seq_gt(seg.end_seq, rs_newest_end_seq));
                if !rs_has_data || is_newer {
                    rs_has_data           = true;
                    rs_prior_delivered    = seg.delivered_at_send;
                    rs_prior_time         = seg.delivered_time_at_send;
                    rs_send_elapsed       = seg.first_sent_ns
                        .saturating_sub(seg.first_send_time_at_send);
                    rs_is_app_limited     = seg.is_app_limited;
                    rs_newest_send_time   = seg.first_sent_ns;
                    rs_newest_end_seq     = seg.end_seq;
                    // Spec: C.first_send_time = P.send_time (of newest delivered)
                    self.bbr.first_send_time = seg.first_sent_ns;
                }
                // RACK: update rack_end_seq/xmit_ns/rtt from ACKed segment
                if seq_gt(seg.end_seq, self.rack_end_seq) {
                    self.rack_end_seq  = seg.end_seq;
                    self.rack_xmit_ns  = seg.last_sent_ns;
                    self.rack_rtt_ns   = now.saturating_sub(seg.last_sent_ns).max(1);
                }
                // Spec: C.delivered += P.data_length; C.delivered_time = now
                // (Actual bbr.delivered update deferred to bbr_on_ack for ordering.)
                self.unacked.remove(i);
            } else {
                i += 1;
            }
        }

        // 2. Rebuild SACK scoreboard from this ACK's blocks (handles reneging).
        self.mark_sack_blocks(opts);

        // 3. Advance snd_una
        self.snd_una = new_ack;
        let _ = old_snd_una;

        // Keep-alive: reset probe state on any ACK progress
        self.last_recv_ns     = now;
        self.keepalive_probes = 0;
        if self.cfg.keepalive_idle_ms > 0 {
            self.keepalive_deadline.arm_from_now_ms(self.cfg.keepalive_idle_ms, now);
        }

        // TS-based RTT (RFC 7323 §4.3): override Karn's sample — TS is Karn-immune
        // TSval ticks are in ms per RFC 7323; convert the ms RTT to ns.
        if self.ts_enabled {
            if let Some(ecr) = opts.ts_ecr {
                if ecr != 0 {
                    let ts_rtt_ms = (self.clock.monotonic_ms() as u32).wrapping_sub(ecr) as u64;
                    rtt_sample = Some(ts_rtt_ms * 1_000_000);
                }
            }
        }

        // 4. RFC 6298 RTT/RTO update (all values in ns)
        if let Some(rtt) = rtt_sample {
            if self.srtt_ns == 0 {
                self.srtt_ns   = rtt;
                self.rttvar_ns = rtt / 2;
            } else {
                let diff       = rtt.abs_diff(self.srtt_ns);
                self.rttvar_ns = self.rttvar_ns - self.rttvar_ns / 4 + diff / 4;
                self.srtt_ns   = self.srtt_ns   - self.srtt_ns   / 8 + rtt / 8;
            }
            // RFC 6298 §2: RTO = SRTT + max(G, 4*RTTVAR).
            self.rto_ns = (self.srtt_ns + (4 * self.rttvar_ns).max(CLOCK_GRANULARITY_NS))
                .max(self.cfg.rto_min_ms * 1_000_000)
                .min(self.cfg.rto_max_ms * 1_000_000);
        }

        // 5. Delivery rate estimation (draft-cheng-iccrg-delivery-rate-estimation §3.4).
        // Compute BEFORE bbr_on_ack updates the delivered counter.
        // BBR uses payload bytes only — SYN/FIN seq-space excluded so the
        // tiny handshake sample (1 byte / RTT) doesn't contaminate max_bw.
        let delivery_rate = if rs_has_data && rs_prior_time > 0 {
            // Update C.delivered_time to mark this delivery event.
            self.bbr.delivered_time = now;
            // Clear app_limited once we've delivered past the marked point.
            if self.bbr.app_limited > 0
                && self.bbr.delivered + acked_data > self.bbr.app_limited
            {
                self.bbr.app_limited = 0;
            }
            let rs_delivered = (self.bbr.delivered + acked_data)
                .saturating_sub(rs_prior_delivered);
            let ack_elapsed  = now.saturating_sub(rs_prior_time);
            let interval     = rs_send_elapsed.max(ack_elapsed);
            // Discard sample if interval < min_rtt (spec §3.4).
            if interval < self.bbr.min_rtt_ns && self.bbr.min_rtt_ns < u64::MAX {
                0
            } else if interval > 0 {
                rs_delivered * 1_000_000_000 / interval
            } else { 0 }
        } else { 0 };

        // 5b. RACK loss detection (RFC 8985 §7.2)
        // RACK must run BEFORE bbr_on_ack so that loss_events_in_round is
        // populated before the Startup filled_pipe exit check evaluates it.
        let newly_lost = self.rack_detect_losses();

        // 5c. BBRv3 congestion control update (after RACK, so loss info is current)
        self.bbr_on_ack(BbrAckState {
            acked_bytes:        acked_data,
            delivery_rate,
            is_app_limited:     rs_is_app_limited,
            rs_prior_delivered,
            newly_lost,
            rtt_ns:             rtt_sample,
            now,
        });

        // 7. Timer management
        if self.unacked.is_empty() {
            self.rto_deadline.disarm();
            self.tlp_deadline.disarm();
            self.rto_count = 0;
        } else {
            // Reset RTO (fresh ACK progress)
            self.rto_deadline.arm_from_now_ns(self.rto_ns, now);
            self.rto_count = 0;
            // Arm TLP if not set
            if !self.tlp_deadline.is_armed() && self.srtt_ns > 0 {
                self.tlp_deadline.arm_from_now_ns(self.tlp_deadline_ns(), now);
            }
        }
    }

    // ── Send buffer drain ────────────────────────────────────────────────────

    fn flush_send_buf(&mut self) {
        let now = self.clock.monotonic_ns();
        loop {
            if self.state != State::Established && self.state != State::CloseWait {
                self.pacing_next.disarm();
                break;
            }
            if self.send_buf.is_empty() {
                self.pacing_next.disarm();
                break;
            }

            // Pacing gate
            if self.pacing_next.is_armed() && !self.pacing_next.is_expired(now) { break; }

            // Peer receive-window gate (RFC 793 §3.7, RFC 7323 §2.3).
            // snd_wnd_raw is the raw (unscaled) value from the peer's header;
            // left-shift by snd_scale to get the true byte count.
            let peer_wnd = (self.snd_wnd_raw as u32) << self.snd_scale;
            let wnd_limit = self.snd_una + peer_wnd;
            if peer_wnd == 0 || seq_ge(self.snd_nxt, wnd_limit) {
                self.pacing_next.disarm();
                // Arm persist timer when blocked by zero window
                if !self.persist_deadline.is_armed() && !self.send_buf.is_empty() {
                    self.persist_backoff_ns = self.rto_ns;
                    self.persist_deadline.arm_from_now_ns(self.persist_backoff_ns, now);
                }
                break;
            }
            // Window opened — cancel persist timer
            self.persist_deadline.disarm();

            // cwnd gate (cwnd already bounded by BBRBoundCwndForModel)
            let bytes_in_flight = self.snd_nxt - self.snd_una;
            if bytes_in_flight >= self.bbr.cwnd {
                self.pacing_next.disarm();
                break;
            }

            // Both gates: cap chunk at the tighter of cwnd room and window room.
            let wnd_room   = (wnd_limit - self.snd_nxt) as usize;
            let available  = ((self.bbr.cwnd - bytes_in_flight) as usize).min(wnd_room);
            let ts_overhead = if self.ts_enabled { 12 } else { 0 };
            let effective_mss = (self.peer_mss as usize).saturating_sub(ts_overhead);
            let chunk_len  = effective_mss
                .min(self.send_buf.len())
                .min(available);
            if chunk_len == 0 { break; }

            // Extract chunk before calling &mut self methods.
            let chunk: Vec<u8> = self.send_buf.drain(..chunk_len).collect();
            let seg_seq        = self.snd_nxt;

            // Piggyback FIN on the last data segment if close() is pending.
            let mut flags = TcpFlags::PSH | TcpFlags::ACK;
            let piggybacked_fin = self.fin_pending && self.send_buf.is_empty();
            if piggybacked_fin { flags |= TcpFlags::FIN; }

            // Send (include Timestamps option when negotiated)
            let ts_arr;
            let ts_slice: &[u8] = if self.ts_enabled {
                ts_arr = self.ts_opt(); &ts_arr
            } else { &[] };
            if self.send_segment(seg_seq, flags, &chunk, ts_slice).is_err() {
                // On TX error, put bytes back and give up.
                let mut tmp = chunk;
                tmp.append(&mut self.send_buf);
                self.send_buf = tmp;
                break;
            }

            // FIN occupies one sequence byte.
            let fin_extra = if piggybacked_fin { 1u32 } else { 0 };

            // Record in retransmit buffer with delivery-rate snapshots.
            // Spec: if no packets in flight, reset timing anchors.
            let inflight_before = (self.snd_nxt - self.snd_una) as u64;
            if inflight_before == 0 {
                self.bbr.first_send_time = now;
                self.bbr.delivered_time  = now;
            }
            let seg_end = seg_seq + chunk.len() as u32 + fin_extra;
            self.unacked.push(TxSegment {
                seq:              seg_seq,
                end_seq:          seg_end,
                flags,
                data:             chunk,
                first_sent_ns:    now,
                last_sent_ns:     now,
                retransmits:      0,
                sacked:           false,
                delivered_at_send:       self.bbr.delivered,
                delivered_time_at_send:  self.bbr.delivered_time,
                first_send_time_at_send: self.bbr.first_send_time,
                is_app_limited:          self.bbr.app_limited > 0,
            });
            self.snd_nxt = seg_end;

            if piggybacked_fin {
                self.fin_pending = false;
                self.state = match self.state {
                    State::CloseWait => State::LastAck,
                    _                => State::FinWait1,
                };
            }

            // Pacing
            let interval = self.pacing_interval_ns();
            if interval > 0 { self.pacing_next.arm_from_now_ns(interval, now); } else { self.pacing_next.disarm(); }

            // Arm/re-arm TLP (RFC 8985 §7.2): deadline depends on
            // FlightSize, so re-compute each time a new segment is sent.
            // When SRTT is unknown (no RTT sample yet), skip TLP — a
            // meaningful PTO cannot be computed and RTO already covers
            // retransmission.
            if self.srtt_ns > 0 {
                self.tlp_deadline.arm_from_now_ns(self.tlp_deadline_ns(), now);
            }

            // Arm RTO
            if !self.rto_deadline.is_armed() {
                self.rto_deadline.arm_from_now_ns(self.rto_ns, now);
            }
        }

        // CheckIfApplicationLimited (spec §3.5): mark app-limited when the
        // sender ran out of data with cwnd room still available.
        if self.send_buf.is_empty() {
            let inflight = (self.snd_nxt - self.snd_una) as u64;
            if inflight < self.bbr.cwnd as u64 {
                let mark = (self.bbr.delivered + inflight).max(1);
                self.bbr.app_limited = mark;
            }
        }
    }

    // ── In-order OOO drain ───────────────────────────────────────────────────

    /// Flush any OOO segments that have become in-order and call on_recv.
    /// If a drained segment carries a FIN, process the state transition.
    fn drain_ooo(&mut self) {
        loop {
            let pos = self.rx_ooo.iter().position(|s| s.seq == self.rcv_nxt);
            let Some(pos) = pos else { break };
            let seg = self.rx_ooo.remove(pos);
            self.rcv_nxt += seg.data.len() as u32;
            self.recv_buf.extend_from_slice(&seg.data);
            let on_recv = self.on_recv;
            on_recv(TcpPacket {
                src: self.dst,
                dst: self.src,
                pdu: &seg.data,
            });
            if seg.has_fin {
                self.process_rx_fin();
                break;
            }
        }
    }

    /// Shared receive-data path for Established and half-close states.
    ///
    /// Handles overlap trimming, in-order delivery (recv_buf + on_recv),
    /// OOO buffering with merge, SACK/D-SACK ACK, keepalive reset, and
    /// deferred FIN processing via [`process_rx_fin`].
    ///
    /// Returns `true` if any in-order data was delivered (rcv_nxt advanced).
    fn receive_data(
        &mut self,
        pdu: &[u8],
        seg_seq: SeqNum,
        has_fin: bool,
    ) -> Result<bool> {
        if pdu.is_empty() && !has_fin { return Ok(false); }

        // RFC 793 §3.3: trim overlap when segment starts before rcv_nxt.
        let (pdu, seg_seq) = if seq_lt(seg_seq, self.rcv_nxt) {
            let overlap = (self.rcv_nxt - seg_seq) as usize;
            if overlap >= pdu.len() {
                let _ = self.send_ctrl(TcpFlags::ACK);
                return Ok(false);
            }
            (&pdu[overlap..], self.rcv_nxt)
        } else {
            (pdu, seg_seq)
        };

        if seg_seq == self.rcv_nxt {
            if self.recv_buf.len() + pdu.len() > self.cfg.recv_buf_max {
                let _ = self.send_ctrl(TcpFlags::ACK);
                return Ok(false);
            }
            self.rcv_nxt += pdu.len() as u32;
            self.recv_buf.extend_from_slice(pdu);
            if has_fin {
                self.process_rx_fin();
            }
            self.drain_ooo();
            {
                let now = self.clock.monotonic_ns();
                self.last_recv_ns     = now;
                self.keepalive_probes = 0;
                if self.cfg.keepalive_idle_ms > 0 {
                    self.keepalive_deadline.arm_from_now_ms(self.cfg.keepalive_idle_ms, now);
                }
            }
            let mut sack_buf = [0u8; 40];
            let max = self.max_sack_blocks();
            let sack_len = if self.sack_ok { self.build_sack_opts(&mut sack_buf, max) } else { 0 };
            self.send_ack_with_opts(&sack_buf[..sack_len])?;
            let on_recv = self.on_recv;
            on_recv(TcpPacket {
                src: self.dst,
                dst: self.src,
                pdu,
            });
            return Ok(true);
        }

        if seq_gt(seg_seq, self.rcv_nxt) {
            // Out-of-order: buffer and SACK.
            let seg_end = seg_seq + pdu.len() as u32;
            let is_dup = self.rx_ooo.iter().any(|s| {
                let s_end = s.seq + s.data.len() as u32;
                seq_ge(seg_seq, s.seq) && seq_le(seg_end, s_end)
            });
            let mut merged = false;
            for s in &mut self.rx_ooo {
                let s_end = s.seq + s.data.len() as u32;
                if seq_ge(seg_end, s.seq) && seq_ge(s_end, seg_seq) {
                    if seq_lt(seg_seq, s.seq) {
                        let prepend = (s.seq - seg_seq) as usize;
                        let mut new_data = pdu[..prepend].to_vec();
                        new_data.extend_from_slice(&s.data);
                        s.data = new_data;
                        s.seq = seg_seq;
                    }
                    if seq_gt(seg_end, s_end) {
                        let overlap = (s_end - seg_seq) as usize;
                        if overlap < pdu.len() {
                            s.data.extend_from_slice(&pdu[overlap..]);
                        }
                    }
                    s.has_fin |= has_fin;
                    merged = true;
                    break;
                }
            }
            let inserted = if !merged && self.rx_ooo.len() < self.cfg.rx_ooo_max {
                self.rx_ooo.push(RxOooSegment { seq: seg_seq, data: pdu.to_vec(), has_fin });
                true
            } else { false };
            if merged || inserted {
                self.rx_ooo.sort_by(|a, b| {
                    if seq_lt(a.seq, b.seq) { core::cmp::Ordering::Less }
                    else if a.seq == b.seq  { core::cmp::Ordering::Equal }
                    else                    { core::cmp::Ordering::Greater }
                });
                let mut i = 0;
                while i + 1 < self.rx_ooo.len() {
                    let a_end = self.rx_ooo[i].seq + self.rx_ooo[i].data.len() as u32;
                    let b_seq = self.rx_ooo[i + 1].seq;
                    if seq_ge(a_end, b_seq) {
                        let b_end = self.rx_ooo[i + 1].seq
                            + self.rx_ooo[i + 1].data.len() as u32;
                        if seq_gt(b_end, a_end) {
                            let overlap = (a_end - b_seq) as usize;
                            let tail: Vec<u8> = self.rx_ooo[i + 1].data[overlap..].to_vec();
                            self.rx_ooo[i].data.extend_from_slice(&tail);
                        }
                        self.rx_ooo[i].has_fin |= self.rx_ooo[i + 1].has_fin;
                        self.rx_ooo.remove(i + 1);
                    } else {
                        i += 1;
                    }
                }
                self.rx_ooo_last = self.rx_ooo.iter()
                    .find(|s| {
                        let s_end = s.seq + s.data.len() as u32;
                        seq_ge(seg_seq, s.seq) && seq_le(seg_seq, s_end)
                    })
                    .map(|s| s.seq)
                    .or(Some(seg_seq));
            }
            let mut sack_buf = [0u8; 40];
            let max = self.max_sack_blocks();
            let sack_len = if self.sack_ok {
                if is_dup && !pdu.is_empty() {
                    let dsack_right = seg_seq + pdu.len() as u32;
                    self.build_dsack_opts(&mut sack_buf, seg_seq, dsack_right, max)
                } else {
                    self.build_sack_opts(&mut sack_buf, max)
                }
            } else { 0 };
            self.send_ack_with_opts(&sack_buf[..sack_len])?;
        }
        Ok(false)
    }

    /// Process peer's FIN: advance rcv_nxt, notify, transition state.
    /// The caller is responsible for sending the ACK (receive_data does this).
    fn process_rx_fin(&mut self) {
        self.rcv_nxt += 1;
        let on_recv = self.on_recv;
        on_recv(TcpPacket {
            src: self.dst,
            dst: self.src,
            pdu: &[],
        });
        match self.state {
            State::Established => { self.state = State::CloseWait; }
            State::FinWait1 => {
                let fin_acked = seq_ge(self.snd_una, self.snd_nxt);
                if fin_acked {
                    let now = self.clock.monotonic_ns();
                    self.rto_deadline.arm_from_now_ms(self.cfg.time_wait_ms, now);
                    self.state = State::TimeWait;
                } else {
                    self.state = State::Closing;
                }
            }
            State::FinWait2 => {
                let now = self.clock.monotonic_ns();
                self.rto_deadline.arm_from_now_ms(self.cfg.time_wait_ms, now);
                self.state = State::TimeWait;
            }
            _ => {}
        }
    }

    // ── Segment processing ───────────────────────────────────────────────────

    pub(crate) fn process_segment(&mut self, raw: &[u8]) -> Result<()> {
        let eth = EthHdr::parse(raw)?;
        if eth.ethertype != EtherType::IPV4 { return Ok(()); }
        let ip_buf = eth.payload(raw);
        // IP + TCP checksums validated by the interface layer before dispatch.
        let ip     = Ipv4Hdr::parse_no_checksum(ip_buf)?;
        if ip.proto != IpProto::TCP || ip.dst != *self.src.ip() { return Ok(()); }
        let tcp_buf = ip.payload(ip_buf);
        let seg     = TcpHdr::parse(tcp_buf)?;
        if seg.dst_port != self.src.port() { return Ok(()); }

        // RST handling (all states that have an established peer)
        if seg.has_flag(TcpFlags::RST) {
            match self.state {
                State::Listen | State::Closed | State::TimeWait => return Ok(()),
                _ => {}
            }
            // SynSent RST validation (RFC 793 §3.4 step 2):
            // RST must carry ACK with valid ack field (SND.UNA <= SEG.ACK <= SND.NXT).
            if self.state == State::SynSent {
                if seg.has_flag(TcpFlags::ACK)
                    && seq_ge(seg.ack, self.snd_una)
                    && seq_le(seg.ack, self.snd_nxt)
                {
                    self.enter_closed();
                    self.last_error = Some(TcpError::Reset);
                    (self.on_error)(TcpError::Reset);
                }
                return Ok(());
            }
            // RFC 5961 §3.2: exact-match RST (SEQ == RCV.NXT) always resets,
            // even when the receive window is zero.
            if seg.seq == self.rcv_nxt {
                self.enter_closed();
                self.last_error = Some(TcpError::Reset);
                (self.on_error)(TcpError::Reset);
                return Ok(());
            }
            // In-window but not exact → challenge ACK.
            let rcv_wnd = (self.cfg.recv_buf_max as u32).saturating_sub(self.recv_buf.len() as u32);
            if seq_gt(seg.seq, self.rcv_nxt) && seq_lt(seg.seq, self.rcv_nxt + rcv_wnd) {
                self.send_challenge_ack();
                return Ok(());
            }
            return Ok(());
        }

        let opts = parse_opts(tcp_buf, seg.data_offset);

        // PAWS — Protection Against Wrapped Sequence numbers (RFC 7323 §5).
        //
        // Once timestamps are negotiated, any segment whose TSval is older than
        // the most recently seen TSval (ts_recent) is from a previous incarnation
        // of the connection and must be discarded.  We skip the check on SYN
        // segments (which establish ts_recent) and in states where a peer
        // address is not yet fixed (Listen, SynSent).
        //
        // Wraparound: a TSval that is more than 2^31 behind ts_recent is
        // considered older.  This handles the case where the peer's clock
        // wraps the full 32-bit range (~49 days at 1-ms resolution).
        if self.ts_enabled
            && !seg.has_flag(TcpFlags::SYN)
            && !matches!(self.state, State::Listen | State::SynSent | State::Closed | State::TimeWait)
        {
            if let Some(tsv) = opts.ts_val {
                if tsv.wrapping_sub(self.ts_recent) >= 0x8000_0000 {
                    // Timestamp is older than ts_recent — PAWS violation.
                    // RFC 7323 §5.2: send a duplicate ACK and discard.
                    let _ = self.send_ctrl(TcpFlags::ACK);
                    return Ok(());
                }
            } else if !seg.has_flag(TcpFlags::RST) {
                // RFC 7323 §3.2: once timestamps are negotiated, non-RST
                // segments without a TS option are not acceptable.
                let _ = self.send_ctrl(TcpFlags::ACK);
                return Ok(());
            }
        }

        // RFC 7323 §4.3: update ts_recent only when SEG.SEQ <= Last.ACK.sent.
        // This prevents ts_recent from advancing on reordered/OOO segments.
        if self.ts_enabled {
            if let Some(tsv) = opts.ts_val {
                if !seq_lt(self.last_ack_sent, seg.seq) {
                    self.ts_recent = tsv;
                }
            }
        }

        // RFC 9293 §3.10.7.4 step 5: in synchronized states, if the ACK bit
        // is off, drop the segment and return.  SYN segments are excluded —
        // step 4 (SYN processing / challenge ACK) precedes step 5.
        if matches!(self.state,
            State::Established | State::FinWait1 | State::FinWait2
            | State::CloseWait | State::Closing | State::LastAck)
        {
            // SYN segments bypass the ACK-bit check (step 4 precedes step 5).
            if !seg.has_flag(TcpFlags::ACK) && !seg.has_flag(TcpFlags::SYN) {
                return Ok(());
            }
            // RFC 9293 §3.10.7.4 step 5: if SEG.ACK > SND.NXT, send an
            // ACK and drop the segment.
            if seg.has_flag(TcpFlags::ACK) && seq_gt(seg.ack, self.snd_nxt) {
                let _ = self.send_ctrl(TcpFlags::ACK);
                return Ok(());
            }
        }

        match self.state {
            // ── LISTEN ──────────────────────────────────────────────────────
            State::Listen => {
                if seg.has_flag(TcpFlags::SYN) && !seg.has_flag(TcpFlags::ACK) {
                    self.dst    = SocketAddrV4::new(ip.src, seg.src_port);
                    self.rcv_nxt = seg.seq + 1;
                    // Learn peer MSS; RFC 793 §3.1: assume 536 if absent
                    self.peer_mss = opts.mss.unwrap_or(536);
                    self.sack_ok = opts.sack_permitted;
                    // Window scaling: only active if both sides include WS in SYN.
                    // RFC 7323 §2.2: omit WS in SYN-ACK when peer omitted it.
                    self.peer_offered_ws = opts.ws_shift.is_some();
                    self.snd_scale = opts.ws_shift.unwrap_or(0);
                    self.rcv_scale = if opts.ws_shift.is_some() { LOCAL_WS_SHIFT } else { 0 };
                    self.snd_wnd_raw = seg.window;
                    if let Some(tsv) = opts.ts_val {
                        self.ts_enabled = true;
                        self.ts_recent  = tsv;
                    }
                    // ECN: if SYN carries both ECE+CWR the peer is ECN-capable.
                    // Respond with SYN-ACK+ECE only (per RFC 3168 §6.1.1).
                    let ecn_synack = if seg.has_flag(TcpFlags::ECE) && seg.has_flag(TcpFlags::CWR) {
                        self.ecn_enabled = true;
                        TcpFlags::ECE
                    } else { TcpFlags::NONE };
                    let syn_opts = self.syn_opts();
                    let isn = self.snd_nxt;
                    self.send_ctrl_opts(TcpFlags::SYN | TcpFlags::ACK | ecn_synack, &syn_opts)?;
                    self.snd_nxt += 1;
                    // Record SYN-ACK in unacked
                    let now = self.clock.monotonic_ns();
                    self.bbr.first_send_time = now;
                    self.bbr.delivered_time  = now;
                    self.unacked.push(TxSegment {
                        seq: isn, end_seq: isn + 1,
                        flags: TcpFlags::SYN | TcpFlags::ACK, data: vec![],
                        first_sent_ns: now, last_sent_ns: now,
                        retransmits: 0, sacked: false,
                        delivered_at_send:       self.bbr.delivered,
                        delivered_time_at_send:  self.bbr.delivered_time,
                        first_send_time_at_send: self.bbr.first_send_time,
                        is_app_limited:          false,
                    });
                    if !self.rto_deadline.is_armed() {
                        self.rto_deadline.arm_from_now_ns(self.rto_ns, now);
                    }
                    self.state = State::SynReceived;
                }
            }

            // ── SYN_RECEIVED ────────────────────────────────────────────────
            State::SynReceived => {
                if seg.has_flag(TcpFlags::ACK) && seq_gt(seg.ack, self.snd_una) && seq_le(seg.ack, self.snd_nxt) {
                    self.on_ack(seg.ack, &opts);
                    self.state = State::Established;
                    self.flush_send_buf();
                }
            }

            // ── SYN_SENT ────────────────────────────────────────────────────
            State::SynSent => {
                if seg.has_flag(TcpFlags::SYN) && seg.has_flag(TcpFlags::ACK) {
                    self.peer_mss = opts.mss.unwrap_or(536);
                    self.sack_ok = opts.sack_permitted;
                    // Window scaling negotiated iff SYN-ACK includes WS option.
                    self.snd_scale = opts.ws_shift.unwrap_or(0);
                    self.rcv_scale = if opts.ws_shift.is_some() { LOCAL_WS_SHIFT } else { 0 };
                    self.snd_wnd_raw = seg.window;
                    if let Some(tsv) = opts.ts_val {
                        self.ts_enabled = true;
                        self.ts_recent  = tsv;
                    }
                    // ECN: SYN-ACK with ECE (without CWR) means peer agrees.
                    if seg.has_flag(TcpFlags::ECE) && !seg.has_flag(TcpFlags::CWR) {
                        self.ecn_enabled = true;
                    }
                    self.rcv_nxt = seg.seq + 1;
                    self.on_ack(seg.ack, &opts);
                    self.send_ctrl(TcpFlags::ACK)?;
                    self.state = State::Established;
                    self.flush_send_buf();
                } else if seg.has_flag(TcpFlags::SYN) {
                    // Simultaneous open (RFC 793 §3.4): bare SYN without ACK.
                    // Transition to SYN_RECEIVED and send SYN+ACK.
                    self.peer_mss = opts.mss.unwrap_or(536);
                    self.sack_ok = opts.sack_permitted;
                    self.snd_scale = opts.ws_shift.unwrap_or(0);
                    self.rcv_scale = if opts.ws_shift.is_some() { LOCAL_WS_SHIFT } else { 0 };
                    self.snd_wnd_raw = seg.window;
                    if let Some(tsv) = opts.ts_val {
                        self.ts_enabled = true;
                        self.ts_recent  = tsv;
                    }
                    self.rcv_nxt = seg.seq + 1;
                    let syn_ack_opts = self.syn_opts();
                    self.send_ctrl_opts(TcpFlags::SYN | TcpFlags::ACK, &syn_ack_opts)?;
                    self.state = State::SynReceived;
                }
            }

            // ── ESTABLISHED ─────────────────────────────────────────────────
            State::Established => {
                // Window check: use actual advertised receive window.
                // RFC 793 §3.3: a segment that starts before rcv_nxt but
                // extends past it carries new data and must be accepted
                // (the overlap is trimmed later, at the delivery path).
                let rcv_wnd   = (self.cfg.recv_buf_max as u32).saturating_sub(self.recv_buf.len() as u32);
                let payload_start_wc = seg.hdr_len().min(tcp_buf.len());
                let seg_end   = seg.seq + (tcp_buf.len() - payload_start_wc) as u32;
                let in_window = (seq_ge(seg.seq, self.rcv_nxt)
                    || seq_gt(seg_end, self.rcv_nxt))
                    && seq_lt(seg.seq, self.rcv_nxt + rcv_wnd);
                let is_keepalive = seg.seq == self.rcv_nxt - 1;

                if !in_window && !is_keepalive {
                    // Duplicate or out-of-window: send ACK and discard.
                    // For duplicate data (seq < rcv_nxt, non-empty) send D-SACK (RFC 2883 §3).
                    let payload_start = seg.hdr_len().min(tcp_buf.len());
                    let pdu = &tcp_buf[payload_start..];
                    if self.sack_ok && !pdu.is_empty() && seq_lt(seg.seq, self.rcv_nxt) {
                        let dsack_left  = seg.seq;
                        let dsack_right = if seq_lt(seg.seq + pdu.len() as u32, self.rcv_nxt) {
                            seg.seq + pdu.len() as u32
                        } else {
                            self.rcv_nxt
                        };
                        let mut sack_buf = [0u8; 40];
                        let max = self.max_sack_blocks();
                        let sack_len = self.build_dsack_opts(&mut sack_buf, dsack_left, dsack_right, max);
                        let _ = self.send_ack_with_opts(&sack_buf[..sack_len]);
                    } else {
                        let _ = self.send_ctrl(TcpFlags::ACK);
                    }
                    return Ok(());
                }

                // RFC 5961 §4: SYN in synchronized state → challenge ACK
                if seg.has_flag(TcpFlags::SYN) {
                    self.send_challenge_ack();
                    return Ok(());
                }

                // Payload slice computed here so dupack can check pdu.is_empty().
                let payload_start = seg.hdr_len().min(tcp_buf.len());
                let pdu           = &tcp_buf[payload_start..];

                // Process cumulative ACK; also update the peer's window.
                if seg.has_flag(TcpFlags::ACK) {
                    let prev_wnd = self.snd_wnd_raw;
                    self.snd_wnd_raw = seg.window;
                    // Process SACK blocks on ALL ACKs (RFC 2018) — advancing
                    // and duplicate — so the sender accumulates full SACK
                    // coverage across multiple dup ACKs.
                    self.mark_sack_blocks(&opts);
                    if seq_gt(seg.ack, self.snd_una) {
                        self.dupack_count = 0;
                        self.on_ack(seg.ack, &opts);
                    } else if seg.ack == self.snd_una
                           && self.snd_una != self.snd_nxt
                           && pdu.is_empty()
                           && seg.window == prev_wnd
                    {
                        self.dupack_count = self.dupack_count.saturating_add(1);
                        // RACK loss detection on dup ACKs — SACK blocks
                        // accumulated above may now satisfy the time condition.
                        let rack_lost = self.rack_detect_losses();
                        // BBRModulateCwndForRecovery on dup-ACK RACK losses
                        if rack_lost > 0 {
                            let min_cwnd = 4 * self.cfg.mss as u32;
                            self.bbr.cwnd = self.bbr.cwnd.saturating_sub(rack_lost as u32)
                                .max(min_cwnd);
                        }
                        if self.dupack_count >= 3 {
                            self.dupack_count = 0;
                            let now = self.clock.monotonic_ns();
                            if let Some(s) = self.unacked.iter().find(|s| !s.sacked) {
                                let (seq, flags, data) = (s.seq, s.flags, s.data.clone());
                                for s in &mut self.unacked {
                                    if s.seq == seq {
                                        s.retransmits += 1;
                                        s.last_sent_ns = now;
                                        // Delivery-rate snapshots (spec: OnPacketSent on retransmit)
                                        s.first_sent_ns = now;
                                        s.delivered_at_send = self.bbr.delivered;
                                        s.delivered_time_at_send = self.bbr.delivered_time;
                                        s.first_send_time_at_send = self.bbr.first_send_time;
                                        s.is_app_limited = self.bbr.app_limited > 0;
                                    }
                                }
                                let syn_arr;
                                let ts_arr;
                                let opts_slice: &[u8] = if flags.has(TcpFlags::SYN) {
                                    syn_arr = self.syn_opts(); &syn_arr
                                } else if self.ts_enabled {
                                    ts_arr = self.ts_opt(); &ts_arr
                                } else { &[] };
                                self.retransmit_in_progress = true;
                                let _ = self.send_segment(seq, flags, &data, opts_slice);
                                self.retransmit_in_progress = false;
                            }
                        }
                    }
                    // D-SACK detection (RFC 2883): first SACK block < snd_una means a
                    // retransmitted segment arrived at the peer as a duplicate → spurious
                    // retransmit due to reordering → widen adaptive reorder window.
                    // Runs for ALL ACKs (advancing, dup, and already-fully-acked), so that
                    // a D-SACK arriving after its companion cumulative ACK is not missed.
                    if opts.sack_count > 0 {
                        if let Some((left, _)) = opts.sack_blocks[0] {
                            if seq_lt(SeqNum::new(left), self.snd_una) {
                                let min_rtt = if self.bbr.min_rtt_ns < u64::MAX { self.bbr.min_rtt_ns } else { self.srtt_ns };
                                let inc = (min_rtt / 4).max(1);
                                // RFC 8985 §6.2: upper-bound is SRTT, not min_RTT.
                                self.rack_reo_wnd_ns =
                                    (self.rack_reo_wnd_ns + inc).min(self.srtt_ns);
                            }
                        }
                    }
                    // Decay rack_reo_wnd_ns once per round (RFC 8985 §7.2).
                    if self.bbr.round_count > self.rack_reo_decay_round {
                        self.rack_reo_decay_round = self.bbr.round_count;
                        self.rack_reo_wnd_ns =
                            self.rack_reo_wnd_ns.saturating_sub(self.rack_reo_wnd_ns / 8 + 1);
                    }
                }

                // ECN: detect CE-marked packets (dscp_ecn low bits == 0b11).
                if self.ecn_enabled && (ip.dscp_ecn & 0x03) == 0x03 {
                    self.ecn_ce_pending = true;
                }
                // ECN: react to ECE on incoming ACKs — reduce cwnd as if loss.
                if self.ecn_enabled && seg.has_flag(TcpFlags::ECE) && !seg.has_flag(TcpFlags::SYN) {
                    self.bbr_on_loss(self.cfg.mss as u64, SeqNum::new(0), SeqNum::new(0));
                    self.ecn_cwr_needed = true;
                }
                // ECN: CWR from sender acknowledges our ECE (RFC 3168 §6.1.3).
                if self.ecn_enabled && seg.has_flag(TcpFlags::CWR) {
                    self.ecn_ce_pending = false;
                }

                // Data / FIN
                //
                // FIN is treated as an OOO-bufferable event: if the FIN's
                // position (seg.seq + pdu.len()) equals rcv_nxt it is
                // processed immediately; otherwise the segment (data + fin
                // flag) is buffered in the OOO queue and drain_ooo handles
                // the state transition once rcv_nxt catches up.
                let has_fin = seg.has_flag(TcpFlags::FIN);
                self.receive_data(pdu, seg.seq, has_fin)?;
            }

            // ── FIN_WAIT_1 ──────────────────────────────────────────────────
            State::FinWait1 => {
                let payload_start = seg.hdr_len().min(tcp_buf.len());
                let pdu           = &tcp_buf[payload_start..];
                let has_fin       = seg.has_flag(TcpFlags::FIN);

                // Process cumulative ACK (may ACK our FIN or earlier data).
                if seg.has_flag(TcpFlags::ACK) && seq_gt(seg.ack, self.snd_una) {
                    self.on_ack(seg.ack, &opts);
                }

                // Deliver payload + FIN using shared reassembly path.
                // receive_data handles OOO, overlap trim, recv_buf overflow,
                // and calls process_rx_fin() for FIN — which transitions state.
                self.receive_data(pdu, seg.seq, has_fin)?;

                // If no FIN and our FIN was ACKed, advance to FinWait2.
                if self.state == State::FinWait1 {
                    let fin_acked = seq_ge(self.snd_una, self.snd_nxt);
                    if fin_acked {
                        self.state = State::FinWait2;
                    }
                }
            }

            // ── FIN_WAIT_2 ──────────────────────────────────────────────────
            State::FinWait2 => {
                let payload_start = seg.hdr_len().min(tcp_buf.len());
                let pdu           = &tcp_buf[payload_start..];
                let has_fin       = seg.has_flag(TcpFlags::FIN);

                // Process ACKs for any remaining retransmit state.
                if seg.has_flag(TcpFlags::ACK) && seq_gt(seg.ack, self.snd_una) {
                    self.on_ack(seg.ack, &opts);
                }

                // Deliver payload + FIN using shared reassembly path.
                // receive_data calls process_rx_fin() for FIN → TimeWait.
                self.receive_data(pdu, seg.seq, has_fin)?;
            }

            // ── CLOSING ─────────────────────────────────────────────────────
            State::Closing => {
                if seg.has_flag(TcpFlags::ACK) {
                    let now = self.clock.monotonic_ns();
                    // Reuse rto_deadline as TIME_WAIT linger timer (field is idle during TimeWait).
                    self.rto_deadline.arm_from_now_ms(self.cfg.time_wait_ms, now);
                    self.state = State::TimeWait;
                }
            }

            // ── LAST_ACK ────────────────────────────────────────────────────
            State::LastAck => {
                if seg.has_flag(TcpFlags::ACK) {
                    self.enter_closed();
                }
            }

            // ── CLOSE_WAIT ───────────────────────────────────────────────────
            // Peer has sent FIN; local app has not yet called close().
            // Process ACKs; don't expect new data from peer.
            State::CloseWait => {
                if seg.has_flag(TcpFlags::ACK) && seq_gt(seg.ack, self.snd_una) {
                    self.on_ack(seg.ack, &opts);
                }
            }

            // ── TIME_WAIT ────────────────────────────────────────────────────
            //
            // RFC 9293 §3.6.1: a retransmitted FIN restarts the 2MSL timer.
            State::TimeWait => {
                if seg.has_flag(TcpFlags::FIN) {
                    let now = self.clock.monotonic_ns();
                    self.rto_deadline.arm_from_now_ms(self.cfg.time_wait_ms, now);
                    let _ = self.send_ctrl(TcpFlags::ACK);
                }
            }

            // ── CLOSED ──────────────────────────────────────────────────────
            State::Closed => {}
        }
        Ok(())
    }

    // ── Constructors ─────────────────────────────────────────────────────────

    /// Active open (FFI path): sends SYN only if `nexthop_ip` is already in the
    /// ARP cache.  Returns [`Error::WouldBlock`] otherwise.
    ///
    /// `nexthop_ip` is the gateway IP for off-subnet destinations, or `dst_ip`
    /// itself for on-link destinations.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_now(
        iface:      &Interface,
        src:        SocketAddrV4,
        dst:        SocketAddrV4,
        nexthop_ip: Ipv4Addr,
        on_recv:    for<'a> fn(TcpPacket<'a>),
        on_error:   fn(TcpError),
        cfg:        TcpConfig,
    ) -> Result<Self> {
        // Verify the nexthop is already in the ARP cache; return WouldBlock if
        // not.  The IpTxFn closure also performs ARP resolution internally, but
        // connect_now must fail fast here rather than queuing a pending SYN.
        iface.arp_queue()
            .lookup_and_refresh(nexthop_ip)
            .ok_or(Error::WouldBlock)?;

        let mut s = Self::new_raw(
            iface.open_ip_tx(), iface.clock().clone(), src, on_recv, on_error,
            cfg,
        );
        s.dst   = dst;
        s.state = State::SynSent;
        let syn_opts = s.syn_opts();
        let isn = s.snd_nxt;
        // Advertise ECN capability in SYN (RFC 3168 §6.1.1).
        s.send_ctrl_opts(TcpFlags::SYN | TcpFlags::ECE | TcpFlags::CWR, &syn_opts)?;
        s.snd_nxt += 1;
        let now = s.clock.monotonic_ns();
        s.bbr.first_send_time = now;
        s.bbr.delivered_time  = now;
        s.unacked.push(TxSegment {
            seq: isn, end_seq: isn + 1,
            flags: TcpFlags::SYN, data: vec![],
            first_sent_ns: now, last_sent_ns: now,
            retransmits: 0, sacked: false,
            delivered_at_send:       0,
            delivered_time_at_send:  now,
            first_send_time_at_send: now,
            is_app_limited:          false,
        });
        s.rto_deadline.arm_from_now_ns(s.rto_ns, now);
        Ok(s)
    }

    /// Passive open: waits for SYN.  Drive with `poll()` until `state == Established`.
    pub fn accept(
        iface:   &Interface,
        src:     SocketAddrV4,
        on_recv: for<'a> fn(TcpPacket<'a>),
        on_error: fn(TcpError),
        cfg:     TcpConfig,
    ) -> Result<Self> {
        let mut s = Self::new_raw(
            iface.open_ip_tx(), iface.clock().clone(), src, on_recv, on_error,
            cfg,
        );
        s.state = State::Listen;
        Ok(s)
    }

    // ── PMTUD helpers ────────────────────────────────────────────────────────

    /// Return true if this socket owns the flow identified by the four-tuple.
    /// Used by PMTUD dispatch in `interface.rs` to match an embedded TCP header.
    pub(crate) fn matches_flow(&self, src: SocketAddrV4, dst: SocketAddrV4) -> bool {
        self.src == src && self.dst == dst
    }

    pub fn src_port(&self) -> u16 { self.src.port() }

    /// Reduce the effective MSS when a "Fragmentation Needed" ICMP is received
    /// for a segment sent by this socket (RFC 1191 Path MTU Discovery).
    pub(crate) fn update_pmtu(&mut self, new_mss: u16) {
        // RFC 1191 §3: "A host MUST never reduce its estimate of the Path
        // MTU below 68 octets."  Minimum MSS = 68 - 20 (IP) - 20 (TCP) = 28.
        const MIN_MSS: u16 = 28;
        let clamped = new_mss.max(MIN_MSS);
        if clamped < self.peer_mss { self.peer_mss = clamped; }
        if clamped < self.cfg.mss  { self.cfg.mss  = clamped; }
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /// Minimum remaining ns across all armed deadlines; `None` if none pending.
    /// Used by `Network::poll_rx_with_timeout` to cap the `ppoll(2)` sleep.
    /// `now_ns` must be a nanosecond timestamp from `Clock::monotonic_ns()`.
    pub fn next_deadline_ns(&self, now_ns: u64) -> Option<u64> {
        [
            self.rto_deadline.remaining_ns(now_ns),
            self.tlp_deadline.remaining_ns(now_ns),
            self.keepalive_deadline.remaining_ns(now_ns),
            self.persist_deadline.remaining_ns(now_ns),
            self.pacing_next.remaining_ns(now_ns),
        ]
        .into_iter().flatten().min()
    }

    /// Snapshot of all TCP timer deadlines for test inspection.
    #[cfg(feature = "test-internals")]
    pub fn timer_state(&self) -> TcpTimerState {
        let now = self.clock.monotonic_ns();
        TcpTimerState {
            rto_ns:       self.rto_deadline.remaining_ns(now),
            tlp_ns:       self.tlp_deadline.remaining_ns(now),
            keepalive_ns: self.keepalive_deadline.remaining_ns(now),
            persist_ns:   self.persist_deadline.remaining_ns(now),
            pacing_ns:    self.pacing_next.remaining_ns(now),
        }
    }

    /// Absolute nanosecond timestamp of the earliest armed deadline
    /// (RTO, TLP, keep-alive, persist, pacing), or `None`.
    pub fn next_deadline_abs_ns(&self) -> Option<u64> {
        [
            self.rto_deadline.abs_ns(),
            self.tlp_deadline.abs_ns(),
            self.keepalive_deadline.abs_ns(),
            self.persist_deadline.abs_ns(),
            self.pacing_next.abs_ns(),
        ]
        .into_iter().flatten().min()
    }

    /// Drive the state machine: timers, retransmit, send-buffer drain.
    ///
    /// RX is now handled by the uplink's poll loop, which calls
    /// [`process_segment`] directly.
    pub fn poll(&mut self) -> Result<()> {
        if self.state == State::Closed {
            return Ok(());
        }
        let now = self.clock.monotonic_ns();

        // ── TLP ──
        if self.tlp_deadline.is_expired(now) {
            self.tlp_deadline.disarm();
            // Send last unacked segment as probe
            if let Some(seg) = self.unacked.last() {
                let tlp_seq   = seg.seq;
                let tlp_flags = seg.flags;
                let tlp_data  = seg.data.clone();
                let ts;
                let opts: &[u8] = if self.ts_enabled { ts = self.ts_opt(); &ts } else { &[] };
                self.retransmit_in_progress = true;
                let _ = self.send_segment(tlp_seq, tlp_flags, &tlp_data, opts);
                self.retransmit_in_progress = false;
            } else if !self.send_buf.is_empty() {
                // Probe with tail of send_buf
                let probe_len = (self.cfg.mss as usize).min(self.send_buf.len());
                let probe: Vec<u8> = self.send_buf[..probe_len].to_vec();
                let seq = self.snd_nxt;
                let ts;
                let opts: &[u8] = if self.ts_enabled { ts = self.ts_opt(); &ts } else { &[] };
                let _ = self.send_segment(seq, TcpFlags::PSH | TcpFlags::ACK, &probe, opts);
            }
            // RFC 8985 §7.3: after sending a TLP probe, re-arm RTO from now
            // to prevent RTO from firing in the same poll cycle (double-send).
            if self.rto_deadline.is_armed() {
                self.rto_deadline.arm_from_now_ns(self.rto_ns, now);
            }
        }

        // ── RTO / TIME_WAIT ──
        if self.rto_deadline.is_expired(now) {
            if self.state == State::TimeWait {
                self.enter_closed();
                return Ok(());
            }
            // Retransmit oldest non-sacked unacked segment
            let oldest = self.unacked.iter().find(|s| !s.sacked).map(|s| {
                (s.seq, s.flags, s.data.clone())
            });
            if let Some((seq, flags, data)) = oldest {
                for s in &mut self.unacked {
                    if s.seq == seq {
                        s.retransmits += 1;
                        s.last_sent_ns = now;
                        // Delivery-rate snapshots (spec: OnPacketSent on retransmit)
                        s.first_sent_ns = now;
                        s.delivered_at_send = self.bbr.delivered;
                        s.delivered_time_at_send = self.bbr.delivered_time;
                        s.first_send_time_at_send = self.bbr.first_send_time;
                        s.is_app_limited = self.bbr.app_limited > 0;
                    }
                }
                let opts_arr;
                let ts_arr;
                let opts_slice: &[u8] = if flags.has(TcpFlags::SYN) {
                    opts_arr = self.syn_opts();
                    &opts_arr
                } else if self.ts_enabled {
                    ts_arr = self.ts_opt();
                    &ts_arr
                } else {
                    &[]
                };
                self.retransmit_in_progress = true;
                let _ = self.send_segment(seq, flags, &data, opts_slice);
                self.retransmit_in_progress = false;
                let end_seq = seq + data.len() as u32;
                self.bbr_on_loss(data.len() as u64, seq, end_seq);
            }
            self.rto_count += 1;
            if self.rto_count >= self.cfg.max_retransmits {
                // RFC 793 §3.8: "If the retransmission timeout is exceeded [...]
                // the connection is aborted."  Send RST to notify the peer.
                let _ = self.send_ctrl(TcpFlags::RST | TcpFlags::ACK);
                self.enter_closed();
                self.last_error = Some(TcpError::Timeout);
                let on_error    = self.on_error;
                on_error(TcpError::Timeout);
                return Ok(());
            }
            self.rto_ns = (self.rto_ns * 2).min(self.cfg.rto_max_ms * 1_000_000);
            self.rto_deadline.arm_from_now_ns(self.rto_ns, now);
            // RFC 8985 §7.2: cancel TLP when RTO fires.
            self.tlp_deadline.disarm();
        }

        // ── Keep-Alive ──
        if self.cfg.keepalive_idle_ms > 0
            && self.keepalive_deadline.is_expired(now)
            && self.state == State::Established
        {
            self.keepalive_probes += 1;
            if self.keepalive_probes > self.cfg.keepalive_count {
                self.enter_closed();
                self.last_error = Some(TcpError::Timeout);
                let on_error    = self.on_error;
                on_error(TcpError::Timeout);
                return Ok(());
            }
            let probe_seq = self.snd_una - 1;
            let ts;
            let opts: &[u8] = if self.ts_enabled { ts = self.ts_opt(); &ts } else { &[] };
            let _ = self.send_segment(probe_seq, TcpFlags::ACK, &[], opts);
            self.keepalive_deadline.arm_from_now_ms(self.cfg.keepalive_interval_ms, now);
        }

        // ── Zero-window persist ──
        if self.persist_deadline.is_expired(now)
            && self.state == State::Established
        {
            // Send a 1-byte window probe (RFC 9293 §3.8.6.1: seq = SND.NXT - 1).
            if !self.send_buf.is_empty() {
                let probe_byte = self.send_buf[0];
                let seq = self.snd_nxt - 1;
                let ts_arr;
                let ts_slice: &[u8] = if self.ts_enabled {
                    ts_arr = self.ts_opt(); &ts_arr
                } else { &[] };
                let _ = self.send_segment(seq, TcpFlags::ACK, &[probe_byte], ts_slice);
            }
            // Exponential backoff, capped at rto_max
            self.persist_backoff_ns = (self.persist_backoff_ns * 2)
                .min(self.cfg.rto_max_ms * 1_000_000);
            self.persist_deadline.arm_from_now_ns(self.persist_backoff_ns, now);
        }

        // ── Drain send buffer ──
        self.flush_send_buf();

        Ok(())
    }

    /// Buffer data for sending.
    ///
    /// RFC 9293 §3.10.2: SEND is valid in SYN-SENT, SYN-RECEIVED (data is
    /// queued for transmission after entering ESTABLISHED), ESTABLISHED, and
    /// CLOSE-WAIT.  Returns [`Error::NotConnected`] in all other states.
    /// Returns [`Error::WouldBlock`] when the send buffer would exceed
    /// [`TcpConfig::send_buf_max`].
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        match self.state {
            State::SynSent | State::SynReceived
            | State::Established | State::CloseWait => {}
            _ => return Err(Error::NotConnected),
        }
        if self.send_buf.len() + data.len() > self.cfg.send_buf_max {
            return Err(Error::WouldBlock);
        }
        self.send_buf.extend_from_slice(data);
        // flush_send_buf only transmits in Established/CloseWait; in
        // SYN-SENT and SYN-RECEIVED the data stays queued until the
        // handshake completes.
        self.flush_send_buf();
        Ok(())
    }

    /// Non-blocking receive.  Returns bytes written into `buf`, or `None`.
    pub fn recv(&mut self, buf: &mut [u8]) -> Option<usize> {
        if self.recv_buf.is_empty() {
            return None;
        }
        let n = self.recv_buf.len().min(buf.len());
        buf[..n].copy_from_slice(&self.recv_buf[..n]);
        self.recv_buf.drain(..n);
        Some(n)
    }

    /// Disarm all timers and clear send state.  Called on every transition
    /// to Closed so stale deadlines cannot spin poll loops.
    fn enter_closed(&mut self) {
        self.state = State::Closed;
        self.rto_deadline.disarm();
        self.tlp_deadline.disarm();
        self.keepalive_deadline.disarm();
        self.persist_deadline.disarm();
        self.pacing_next.disarm();
        self.send_buf.clear();
    }

    /// Abortive close: send RST and immediately transition to Closed.
    pub fn abort(&mut self) -> Result<()> {
        match self.state {
            State::Closed | State::Listen => {}
            _ => { let _ = self.send_ctrl_opts(TcpFlags::RST, &[]); }
        }
        self.enter_closed();
        Ok(())
    }

    /// Initiate graceful close (sends FIN).
    pub fn close(&mut self) -> Result<()> {
        match self.state {
            State::Established => {
                if self.send_buf.is_empty() {
                    let fin_seq = self.snd_nxt;
                    self.send_ctrl(TcpFlags::FIN | TcpFlags::ACK)?;
                    self.snd_nxt += 1;
                    self.record_fin(fin_seq);
                    self.state = State::FinWait1;
                } else {
                    // Piggyback FIN on the last data segment.
                    self.fin_pending = true;
                    self.flush_send_buf();
                    // If flush didn't drain (pacing/cwnd gate), FIN will be
                    // piggybacked on a future flush_send_buf call.
                }
            }
            State::CloseWait => {
                if self.send_buf.is_empty() {
                    let fin_seq = self.snd_nxt;
                    self.send_ctrl(TcpFlags::FIN | TcpFlags::ACK)?;
                    self.snd_nxt += 1;
                    self.record_fin(fin_seq);
                    self.state = State::LastAck;
                } else {
                    self.fin_pending = true;
                    self.flush_send_buf();
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Push a FIN into the retransmit buffer and arm RTO so a lost FIN is
    /// retransmitted.
    fn record_fin(&mut self, fin_seq: SeqNum) {
        let now = self.clock.monotonic_ns();
        if (self.snd_nxt - self.snd_una) as u64 == 0 {
            self.bbr.first_send_time = now;
            self.bbr.delivered_time  = now;
        }
        self.unacked.push(TxSegment {
            seq:           fin_seq,
            end_seq:       fin_seq + 1, // FIN occupies 1 sequence byte
            flags:         TcpFlags::FIN | TcpFlags::ACK,
            data:          Vec::new(),
            first_sent_ns: now,
            last_sent_ns:  now,
            retransmits:   0,
            sacked:        false,
            delivered_at_send:       self.bbr.delivered,
            delivered_time_at_send:  self.bbr.delivered_time,
            first_send_time_at_send: self.bbr.first_send_time,
            is_app_limited:          self.bbr.app_limited > 0,
        });
        if !self.rto_deadline.is_armed() {
            self.rto_deadline.arm_from_now_ns(self.rto_ns, now);
        }
    }

}

// ── Test-internals accessors ────────────────────────────────────────────────

#[cfg(feature = "test-internals")]
impl TcpSocket {
    pub fn bbr_cwnd(&self) -> u32 { self.bbr.cwnd }
    pub fn bbr_inflight_shortterm(&self) -> u32 { self.bbr.inflight_shortterm }
    pub fn bbr_inflight_longterm(&self) -> u32 { self.bbr.inflight_longterm }
    pub fn bbr_phase(&self) -> BbrPhase { self.bbr.phase }
    pub fn bbr_max_bw(&self) -> u64 { self.bbr.max_bw }
    pub fn bbr_bw_shortterm(&self) -> u64 { self.bbr.bw_shortterm }
    pub fn bbr_bw_latest(&self) -> u64 { self.bbr.bw_latest }
    pub fn bbr_inflight_latest(&self) -> u64 { self.bbr.inflight_latest }
    pub fn bbr_min_rtt_ns(&self) -> u64 { self.bbr.min_rtt_ns }
    pub fn bbr_pacing_rate_bps(&self) -> u64 { self.pacing_rate_bps() }
    pub fn bbr_round_count(&self) -> u64 { self.bbr.round_count }
    pub fn bbr_filled_pipe(&self) -> bool { self.bbr.filled_pipe }
    pub fn bbr_loss_in_round(&self) -> bool { self.bbr.loss_in_round }
    pub fn bbr_loss_bytes_round(&self) -> u64 { self.bbr.loss_bytes_round }
    pub fn bbr_loss_events_in_round(&self) -> u32 { self.bbr.loss_events_in_round }
    pub fn bbr_acked_bytes_round(&self) -> u64 { self.bbr.acked_bytes_round }
    pub fn bbr_prior_cwnd(&self) -> u32 { self.bbr.prior_cwnd }
    pub fn rack_reo_wnd_ns(&self) -> u64 { self.rack_reo_wnd_ns }
    pub fn rack_end_seq(&self) -> u32 { self.rack_end_seq.0 }
    pub fn rack_xmit_ns(&self) -> u64 { self.rack_xmit_ns }
    pub fn dupack_count(&self) -> u8 { self.dupack_count }
    pub fn snd_wnd(&self) -> u32 { (self.snd_wnd_raw as u32) << self.snd_scale }
    pub fn srtt_ns(&self) -> u64 { self.srtt_ns }
    pub fn rttvar_ns(&self) -> u64 { self.rttvar_ns }
    pub fn rto_ns(&self) -> u64 { self.rto_ns }
    pub fn srtt_ms(&self) -> u64 { self.srtt_ns / 1_000_000 }
    pub fn rttvar_ms(&self) -> u64 { self.rttvar_ns / 1_000_000 }
    pub fn rto_ms(&self) -> u64 { self.rto_ns / 1_000_000 }
    pub fn sack_ok(&self) -> bool { self.sack_ok }
    pub fn ts_enabled(&self) -> bool { self.ts_enabled }
    pub fn ecn_enabled(&self) -> bool { self.ecn_enabled }
    pub fn peer_mss(&self) -> u16 { self.peer_mss }
    pub fn snd_nxt(&self) -> u32 { self.snd_nxt.as_u32() }
    /// Advance snd_nxt to cover injected data that bypassed the send path.
    pub fn advance_snd_nxt_to(&mut self, seq: u32) {
        let seq = SeqNum::new(seq);
        if seq_gt(seq, self.snd_nxt) { self.snd_nxt = seq; }
    }
    pub fn snd_una(&self) -> u32 { self.snd_una.as_u32() }
    pub fn rcv_nxt(&self) -> u32 { self.rcv_nxt.as_u32() }
    pub fn bytes_in_flight(&self) -> u32 { self.snd_nxt - self.snd_una }
    pub fn send_buf_len(&self) -> usize { self.send_buf.len() }
    pub fn bbr_delivered(&self) -> u64 { self.bbr.delivered }
    pub fn bbr_next_round_delivered(&self) -> u64 { self.bbr.next_round_delivered }
    pub fn unacked_len(&self) -> usize { self.unacked.len() }
    #[cfg(feature = "test-internals")]
    pub fn sacked_count(&self) -> usize { self.unacked.iter().filter(|s| s.sacked).count() }
    #[cfg(feature = "test-internals")]
    pub fn challenge_ack_count(&self) -> u8 { self.challenge_ack_count }
    pub fn rcv_scale(&self) -> u8 { self.rcv_scale }
    pub fn snd_scale(&self) -> u8 { self.snd_scale }
    pub fn ts_recent(&self) -> u32 { self.ts_recent }
    pub fn last_ack_sent(&self) -> u32 { self.last_ack_sent.as_u32() }
    pub fn bbr_history(&self) -> &[BbrSnapshot] { &self.bbr.history }
    pub fn bbr_snapshot(&self) -> BbrSnapshot {
        BbrSnapshot {
            phase:              self.bbr.phase,
            cwnd:               self.bbr.cwnd,
            pacing_rate_bps:    self.pacing_rate_bps(),
            max_bw:             self.bbr.max_bw,
            bw_shortterm:       self.bbr.bw_shortterm,
            bw_latest:          self.bbr.bw_latest,
            inflight_shortterm: self.bbr.inflight_shortterm,
            inflight_longterm:  self.bbr.inflight_longterm,
            inflight_latest:    self.bbr.inflight_latest,
            min_rtt_ns:         self.bbr.min_rtt_ns,
            round_count:        self.bbr.round_count,
            loss_in_round:      self.bbr.loss_in_round,
            delivered:          self.bbr.delivered,
            filled_pipe:        self.bbr.filled_pipe,
            bytes_in_flight:    self.snd_nxt - self.snd_una,
            prior_cwnd:         self.bbr.prior_cwnd,
            cycle_stamp_ns:     self.bbr.cycle_stamp_ns,
            rounds_since_bw_probe: self.bbr.rounds_since_bw_probe,
            bw_probe_wait_ns:   self.bbr.bw_probe_wait_ns,
            app_limited:        self.bbr.app_limited,
            loss_bytes_round:   self.bbr.loss_bytes_round,
            acked_bytes_round:  self.bbr.acked_bytes_round,
            loss_events_in_round: self.bbr.loss_events_in_round,
        }
    }
    pub fn bbr_clear_history(&mut self) { self.bbr.history.clear(); }
}

// ── L4 dispatch ───────────────────────────────────────────────────────────────

/// Dispatch a TCP segment (already copied off the ring) to the matching socket.
///
/// Parses enough of the frame to find the destination port, then hands the
/// full raw frame to the matching socket's state machine.  Sends RST if no
/// socket matches.
pub fn dispatch(
    iface:   &mut Interface,
    raw:     &[u8],
    sockets: &mut [TcpSocket],
) -> Result<()> {
    let eth     = EthHdr::parse(raw)?;
    let ip_buf  = eth.payload(raw);
    // IP + TCP checksums validated by the interface layer before dispatch.
    let ip      = Ipv4Hdr::parse_no_checksum(ip_buf)?;
    let tcp_buf = ip.payload(ip_buf);
    let seg     = TcpHdr::parse(tcp_buf)?;

    for s in sockets.iter_mut() {
        if s.src_port() == seg.dst_port {
            s.process_segment(raw)?;
            return Ok(());
        }
    }
    let _ = iface.send_tcp_rst(raw);
    Ok(())
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use crate::timers::Clock;

    fn noop_recv(_: TcpPacket<'_>) {}
    fn noop_error(_: TcpError) {}

    /// Build a TcpSocket in Established state with a no-op TX closure.
    /// The peer window and cwnd are set large enough for flush_send_buf
    /// to actually send data.
    fn established_socket(clock: Clock, cfg: TcpConfig) -> TcpSocket {
        let tx: crate::IpTxFn = Rc::new(|_, _, _, _| Ok(()));
        let src = core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(10, 0, 0, 1), 5000,
        );
        let mut s = TcpSocket::new_raw(tx, clock, src, noop_recv, noop_error, cfg);
        s.state = State::Established;
        s.dst = core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(10, 0, 0, 2), 8080,
        );
        // Open peer window so flush_send_buf can proceed.
        s.snd_wnd_raw = 65535;
        s
    }

    #[test]
    fn tlp_not_armed_when_srtt_is_zero() {
        let clock = Clock::default();
        let cfg = TcpConfig::default();
        let mut s = established_socket(clock, cfg);

        // Precondition: SRTT is unknown (no RTT sample yet).
        assert_eq!(s.srtt_ns, 0, "srtt_ns should be 0 before any RTT sample");
        assert!(!s.tlp_deadline.is_armed(), "TLP should not be armed initially");

        // Send data — this calls flush_send_buf which is where TLP arming lives.
        s.send(b"hello").unwrap();

        // TLP must NOT be armed because SRTT == 0 — we cannot compute a
        // meaningful PTO.  RTO covers retransmission instead.
        assert!(!s.tlp_deadline.is_armed(),
            "TLP deadline must not be armed when SRTT is 0");
        // RTO should be armed (it covers retransmission when TLP is skipped).
        assert!(s.rto_deadline.is_armed(),
            "RTO deadline should be armed after sending data");
    }

    #[test]
    fn tlp_armed_when_srtt_is_nonzero() {
        let clock = Clock::default();
        let cfg = TcpConfig::default();
        let mut s = established_socket(clock, cfg);

        // Simulate having an RTT sample.
        s.srtt_ns = 50_000_000; // 50 ms

        s.send(b"hello").unwrap();

        // With a valid SRTT, TLP should be armed.
        assert!(s.tlp_deadline.is_armed(),
            "TLP deadline should be armed when SRTT > 0");
    }
}
