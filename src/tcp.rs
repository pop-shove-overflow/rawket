/// Full TCP state machine: RFC 793 + SACK (RFC 2018) + RACK-TLP (RFC 8985) + BBRv3.
use alloc::{vec, vec::Vec};
use core::fmt;
use core::net::{Ipv4Addr, SocketAddrV4};
use crate::{
    eth::{EthHdr, EtherType, MacAddr},
    interface::Interface,
    ip::{
        checksum_add, checksum_finish, pseudo_header_acc, IpProto, Ipv4Hdr,
        MIN_HDR_LEN as IP_HDR_LEN,
    },
    timers,
    Error, Result,
};

pub const HDR_LEN: usize = 20;

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

    #[inline] pub fn has(self, f: Self) -> bool { self.0 & f.0 != 0 }
    #[inline] pub fn is_empty(self) -> bool      { self.0 == 0 }
    #[inline] pub fn bits(self) -> u8            { self.0 }
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

/// A fixed-point multiplier stored as × 100.
///
/// `ScaledFloat::new(125)` represents 1.25.
/// Use [`apply`] to multiply a `u64` by this factor.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ScaledFloat(u32);

impl ScaledFloat {
    pub const fn new(x100: u32) -> Self { Self(x100) }
    /// Returns `v × self / 100`.
    #[inline]
    pub fn apply(self, v: u64) -> u64 { v * self.0 as u64 / 100 }
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
const RECV_BUF_MAX: u32 = 1 << 20; // 1 MiB

/// Window scale shift we advertise (RFC 1323 §2).  With shift=4 one window
/// unit represents 16 bytes, giving a max window of 16 × 65535 ≈ 1 MiB.
const LOCAL_WS_SHIFT: u8 = 4;

/// TIME_WAIT duration (2×MSL = 2×60s).
const TIME_WAIT_MS: u64 = 120_000;

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
    /// Maximum out-of-order segments buffered per connection before
    /// discarding.  SACK blocks are emitted for at most 4 OOO segments
    /// regardless of this value.  Default: 8.
    pub rx_ooo_max:                usize,
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
            rx_ooo_max:                8,
        }
    }
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
    pub eth_src: MacAddr,
    pub eth_dst: MacAddr,
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
    first_sent_ms:    u64,
    last_sent_ms:     u64,
    retransmits:      u8,
    sacked:           bool,
    dtime_at_send:    u64,   // bbr.delivered_ms at send time
}

// ── Out-of-order receive buffer ───────────────────────────────────────────────

struct RxOooSegment {
    seq:  SeqNum,
    data: Vec<u8>,
}

// ── BBRv3 ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum BbrPhase {
    Startup,
    Drain,
    ProbeBw,
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
    bw_lo:                u64,           // lower bound from loss
    bw_samples:           [BwSample; 10],
    bw_sample_idx:        usize,
    // RTT
    min_rtt_ms:           u64,
    min_rtt_stamp_ms:     u64,
    // Congestion window
    cwnd:                 u32,
    inflight_lo:          u32,
    inflight_hi:          u32,
    // Delivery rate tracking
    delivered:            u64,           // total bytes ACKed
    delivered_ms:         u64,           // timestamp of last delivery
    // Round counting
    round_count:          u64,
    next_round_delivered: u64,
    // STARTUP convergence
    filled_pipe:          bool,
    full_bw_at_round:     u64,
    full_bw_cnt:          u8,
    // PROBE_BW cycling
    probe_bw_in_up:       bool,
    cycle_stamp_ms:       u64,
    // PROBE_RTT
    probe_rtt_done_ms:    u64,           // 0 = not in PROBE_RTT
    prior_cwnd:           u32,
    last_probe_rtt_ms:    u64,
    // Per-round loss tracking
    loss_bytes_round:     u64,
    acked_bytes_round:    u64,
}

impl BbrState {
    fn new(cfg: &TcpConfig) -> Self {
        let init_cwnd = cfg.initial_cwnd_pkts * cfg.mss as u32;
        BbrState {
            phase:                BbrPhase::Startup,
            max_bw:               0,
            bw_lo:                u64::MAX,
            bw_samples:           [BwSample { round: 0, bw: 0 }; 10],
            bw_sample_idx:        0,
            min_rtt_ms:           u64::MAX,
            min_rtt_stamp_ms:     0,
            cwnd:                 init_cwnd,
            inflight_lo:          u32::MAX,
            inflight_hi:          u32::MAX,
            delivered:            0,
            delivered_ms:         0,
            round_count:          0,
            next_round_delivered: 0,
            filled_pipe:          false,
            full_bw_at_round:     0,
            full_bw_cnt:          0,
            probe_bw_in_up:       true,
            cycle_stamp_ms:       0,
            probe_rtt_done_ms:    0,
            prior_cwnd:           init_cwnd,
            last_probe_rtt_ms:    0,
            loss_bytes_round:     0,
            acked_bytes_round:    0,
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
    tx:          crate::TxFn,
    src_mac:     MacAddr,
    dst_mac:     MacAddr,
    src:         SocketAddrV4,
    dst:         SocketAddrV4,
    nexthop_ip:  Ipv4Addr,
    pub state:   State,
    snd_nxt:     SeqNum,
    snd_una:     SeqNum,
    rcv_nxt:     SeqNum,
    tx_id:       u16,
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

    // RTT / RTO (RFC 6298)
    srtt_ms:     u64,   // 0 = no sample yet
    rttvar_ms:   u64,
    rto_ms:      u64,

    // RACK
    rack_end_seq:    SeqNum,
    rack_xmit_ms:    u64,
    /// Extra reorder tolerance added to the RACK timer deadline (ms).
    /// Increased on D-SACK detection; decays toward 0 over time.
    rack_reo_wnd_ms: u64,

    // Wall-clock deadlines (0 = not armed)
    rto_deadline_ms: u64,
    tlp_deadline_ms: u64,
    rto_count:       u8,

    // Duplicate ACK counter (fast retransmit)
    dupack_count:    u8,

    // TCP Timestamps (RFC 7323)
    ts_enabled:      bool,   // both sides negotiated timestamps
    ts_recent:       u32,    // last TSval received from peer (echoed as TSecr)

    // ECN (RFC 3168)
    ecn_enabled:    bool,   // both sides negotiated ECN at SYN time
    ecn_ce_pending: bool,   // received CE-marked IP; echo ECE in next ACK
    ecn_cwr_needed: bool,   // received ECE in ACK; send CWR on next data seg

    // Keep-alive
    last_recv_ms:          u64,   // last time we received data or ACK progress
    keepalive_deadline_ms: u64,   // next probe wall-clock time; 0 = not armed
    keepalive_probes:      u8,    // probes sent since last activity

    // BBRv3
    bbr: BbrState,

    // Zero-window persist
    persist_deadline_ms: u64,   // 0 = not armed
    persist_backoff_ms:  u64,   // current persist interval (doubles each probe)

    // Software pacing
    pacing_next_ms: u64,

    // Config
    cfg: TcpConfig,

    /// Populated when the socket transitions to Closed due to RST or Timeout.
    /// Checked by the FFI wrapper after each `poll()`.
    pub last_error: Option<TcpError>,
}

impl TcpSocket {
    #[allow(clippy::too_many_arguments)]
    fn new_raw(
        tx:        crate::TxFn,
        src_mac:   MacAddr,
        src:       SocketAddrV4,
        on_recv:   for<'a> fn(TcpPacket<'a>),
        on_error:  fn(TcpError),
        cfg:       TcpConfig,
    ) -> Self {
        let isn   = SeqNum::new(random_u32());
        let rto   = cfg.rto_min_ms;
        let bbr   = BbrState::new(&cfg);
        TcpSocket {
            tx,
            src_mac,
            dst_mac:         MacAddr::ZERO,
            src,
            dst:             SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            nexthop_ip:      Ipv4Addr::UNSPECIFIED,
            state:           State::Closed,
            snd_nxt:         isn,
            snd_una:         isn,
            rcv_nxt:         SeqNum::new(0),
            tx_id:           0,
            on_recv,
            on_error,
            send_buf:        Vec::new(),
            unacked:         Vec::new(),
            sack_ok:         false,
            peer_mss:        cfg.mss,
            snd_scale:       0,
            snd_wnd_raw:     0,
            rcv_scale:       0,
            recv_buf:        Vec::new(),
            rx_ooo:          Vec::new(),
            srtt_ms:         0,
            rttvar_ms:       0,
            rto_ms:          rto,
            rack_end_seq:    isn,
            rack_xmit_ms:    0,
            rto_deadline_ms:       0,
            tlp_deadline_ms:       0,
            rto_count:             0,
            dupack_count:          0,
            rack_reo_wnd_ms:       0,
            ts_enabled:            false,
            ts_recent:             0,
            ecn_enabled:           false,
            ecn_ce_pending:        false,
            ecn_cwr_needed:        false,
            last_recv_ms:          0,
            keepalive_deadline_ms: 0,
            keepalive_probes:      0,
            bbr,
            persist_deadline_ms: 0,
            persist_backoff_ms:  0,
            pacing_next_ms:  0,
            cfg,
            last_error:      None,
        }
    }

    // ── SYN option bytes (MSS + WS + SACK-Permitted + Timestamps, 24 bytes) ──

    fn syn_opts(&self) -> [u8; 24] {
        let mss = self.cfg.mss;
        let [t0, t1, t2, t3] = (timers::now_ms() as u32).to_be_bytes();
        [
            0x02, 0x04, (mss >> 8) as u8, mss as u8,   // MSS (4)
            0x03, 0x03, LOCAL_WS_SHIFT, 0x01,            // WS (3) + NOP pad (1)
            0x04, 0x02, 0x01, 0x01,                      // SACK-Permitted (2) + 2 NOPs
            0x01, 0x01, 0x08, 0x0a,                      // NOP NOP kind=8 len=10
            t0, t1, t2, t3,                              // TSval = now
            0x00, 0x00, 0x00, 0x00,                      // TSecr = 0 (per RFC 7323 §3.2)
        ]
    }

    // ── TCP Timestamps option (NOP NOP kind=8 len=10 TSval TSecr, 12 bytes) ──

    fn ts_opt(&self) -> [u8; 12] {
        let [t0, t1, t2, t3] = (timers::now_ms() as u32).to_be_bytes();
        let [e0, e1, e2, e3] = self.ts_recent.to_be_bytes();
        [0x01, 0x01, 0x08, 0x0a, t0, t1, t2, t3, e0, e1, e2, e3]
    }

    // ── SACK option for receiver (up to 4 OOO blocks, max 36 bytes) ─────────

    /// Returns the number of bytes written into `buf`.  Buf must be at least 36 bytes.
    fn build_sack_opts(&self, buf: &mut [u8; 40]) -> usize {
        let n = self.rx_ooo.len().min(4);
        if n == 0 { return 0; }
        let opt_len = 2 + 8 * n; // SACK kind (1) + len (1) + 8*n
        let total   = 2 + opt_len; // 2 NOPs + kind + len + blocks
        buf[0] = 0x01; // NOP
        buf[1] = 0x01; // NOP
        buf[2] = 0x05; // SACK kind
        buf[3] = opt_len as u8;
        for (i, ooo) in self.rx_ooo.iter().take(4).enumerate() {
            let left  = ooo.seq;
            let right = ooo.seq + ooo.data.len() as u32;
            let off   = 4 + i * 8;
            buf[off..off + 4].copy_from_slice(&left.as_u32().to_be_bytes());
            buf[off + 4..off + 8].copy_from_slice(&right.as_u32().to_be_bytes());
        }
        total
    }

    // ── Frame builder / sender ───────────────────────────────────────────────

    /// Send a TCP segment with explicit sequence number, flags, payload and options.
    /// `opts` must be pre-padded to a multiple of 4 bytes.
    fn send_segment(&mut self, seq: SeqNum, mut flags: TcpFlags, payload: &[u8], opts: &[u8]) -> Result<()> {
        debug_assert!(opts.len().is_multiple_of(4));

        // ECN flag injection (RFC 3168):
        // • ECE on ACK-only segments when we received a CE-marked IP datagram.
        // • CWR on the next data segment after we received an ECE-bearing ACK.
        if self.ecn_enabled {
            if flags.has(TcpFlags::ACK) && !flags.has(TcpFlags::SYN) && self.ecn_ce_pending {
                flags |= TcpFlags::ECE;
                self.ecn_ce_pending = false;
            }
            if !payload.is_empty() && self.ecn_cwr_needed {
                flags |= TcpFlags::CWR;
                self.ecn_cwr_needed = false;
            }
        }

        let tcp_hdr_len = HDR_LEN + opts.len();
        let ip_total    = (IP_HDR_LEN + tcp_hdr_len + payload.len()) as u16;
        let frame_len   = crate::eth::HDR_LEN + IP_HDR_LEN + tcp_hdr_len + payload.len();

        let mut buf   = alloc::vec![0u8; frame_len];
        let frame     = &mut buf[..];

        EthHdr { dst: self.dst_mac, src: self.src_mac, ethertype: EtherType::IPV4 }.emit(frame)?;

        // ECT(0) = 0x02 marks outgoing data segments as ECN-capable transport.
        let dscp_ecn = if self.ecn_enabled && !payload.is_empty() { 0x02u8 } else { 0u8 };

        self.tx_id = self.tx_id.wrapping_add(1);
        Ipv4Hdr {
            ihl: 5, dscp_ecn, total_len: ip_total,
            id: self.tx_id, flags_frag: 0x4000, ttl: 64,
            proto: IpProto::TCP, src: *self.src.ip(), dst: *self.dst.ip(),
        }.emit(&mut frame[crate::eth::HDR_LEN..])?;

        let tcp_off = crate::eth::HDR_LEN + IP_HDR_LEN;
        let data_offset = (tcp_hdr_len / 4) as u8;

        frame[tcp_off..tcp_off + 2].copy_from_slice(&self.src.port().to_be_bytes());
        frame[tcp_off + 2..tcp_off + 4].copy_from_slice(&self.dst.port().to_be_bytes());
        frame[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.as_u32().to_be_bytes());
        frame[tcp_off + 8..tcp_off + 12].copy_from_slice(&self.rcv_nxt.as_u32().to_be_bytes());
        frame[tcp_off + 12] = data_offset << 4;
        frame[tcp_off + 13] = flags.0;
        // Advertise how much receive buffer space we have, scaled by rcv_scale.
        // Cap at u16::MAX; if rcv_scale is 0 (not negotiated) this is bytes-exact.
        let recv_headroom = RECV_BUF_MAX.saturating_sub(self.recv_buf.len() as u32);
        let adv_window    = (recv_headroom >> self.rcv_scale).min(u16::MAX as u32) as u16;
        frame[tcp_off + 14..tcp_off + 16].copy_from_slice(&adv_window.to_be_bytes());
        frame[tcp_off + 16..tcp_off + 18].copy_from_slice(&[0, 0]); // checksum placeholder
        frame[tcp_off + 18..tcp_off + 20].copy_from_slice(&[0, 0]); // urgent

        if !opts.is_empty() {
            frame[tcp_off + HDR_LEN..tcp_off + HDR_LEN + opts.len()].copy_from_slice(opts);
        }
        if !payload.is_empty() {
            frame[tcp_off + tcp_hdr_len..].copy_from_slice(payload);
        }

        // Compute TCP checksum over header (including options) + payload.
        let seg_total = (tcp_hdr_len + payload.len()) as u16;
        let acc = pseudo_header_acc(self.src.ip(), self.dst.ip(), IpProto::TCP, seg_total);
        let acc = checksum_add(acc, &frame[tcp_off..tcp_off + tcp_hdr_len + payload.len()]);
        let csum = checksum_finish(acc);
        frame[tcp_off + 16..tcp_off + 18].copy_from_slice(&csum.to_be_bytes());

        (self.tx)(frame)
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

    /// Convenience: control segment with options (e.g. SYN with MSS).
    fn send_ctrl_opts(&mut self, flags: TcpFlags, opts: &[u8]) -> Result<()> {
        let seq = self.snd_nxt;
        self.send_segment(seq, flags, &[], opts)
    }

    // ── BBR helpers ──────────────────────────────────────────────────────────

    /// Returns (pacing_gain_x100, cwnd_gain_x100).
    fn bbr_gains(&self) -> (ScaledFloat, ScaledFloat) {
        match self.bbr.phase {
            BbrPhase::Startup  => (ScaledFloat::new(288), ScaledFloat::new(200)),
            BbrPhase::Drain    => (ScaledFloat::new(35),  ScaledFloat::new(200)),
            BbrPhase::ProbeBw  => {
                if self.bbr.probe_bw_in_up {
                    (ScaledFloat::new(125), ScaledFloat::new(225))
                } else {
                    (ScaledFloat::new(75),  ScaledFloat::new(200))
                }
            }
            BbrPhase::ProbeRtt => (ScaledFloat::new(100), ScaledFloat::new(100)),
        }
    }

    /// Bytes-per-second pacing rate given current BBR state.
    fn pacing_rate_bps(&self) -> u64 {
        let effective_bw = if self.bbr.bw_lo == u64::MAX {
            self.bbr.max_bw
        } else {
            self.bbr.max_bw.min(self.bbr.bw_lo)
        };
        if effective_bw == 0 { return 0; }
        let (pacing_gain, _) = self.bbr_gains();
        pacing_gain.apply(effective_bw)
    }

    /// Milliseconds between MSS-sized sends at current pacing rate.
    fn pacing_interval_ms(&self) -> u64 {
        let rate = self.pacing_rate_bps();
        if rate == 0 { return 0; } // 0 = send immediately
        self.cfg.mss as u64 * 1_000 / rate
    }

    /// Update BBR windowed-max bandwidth and cwnd after receiving ACKs.
    fn bbr_on_ack(&mut self, acked_bytes: u64, rtt_ms: Option<u64>, now: u64) {
        if acked_bytes == 0 { return; }

        // Deliver accounting
        self.bbr.delivered     += acked_bytes;
        self.bbr.acked_bytes_round += acked_bytes;

        // Round counting: advance round when we've ACKed past next_round_delivered.
        if self.bbr.delivered >= self.bbr.next_round_delivered {
            self.bbr.round_count          += 1;
            let bytes_in_flight           = (self.snd_nxt - self.snd_una) as u64;
            self.bbr.next_round_delivered = self.bbr.delivered + bytes_in_flight.max(1);
            // Reset per-round loss tracking at new round
            self.bbr.loss_bytes_round  = 0;
            self.bbr.acked_bytes_round = 0;
        }

        // Bandwidth sample: bytes delivered / time since oldest segment was sent.
        if self.bbr.delivered_ms > 0 {
            let elapsed_ms = now.saturating_sub(self.bbr.delivered_ms).max(1);
            let bw_sample  = acked_bytes * 1_000 / elapsed_ms; // bytes/sec
            let n_rounds   = (self.cfg.bbr_bw_filter_rounds as usize).clamp(1, 10);
            let idx        = self.bbr.bw_sample_idx;
            self.bbr.bw_samples[idx] = BwSample { round: self.bbr.round_count, bw: bw_sample };
            self.bbr.bw_sample_idx   = (idx + 1) % n_rounds;
            // Windowed max over last n_rounds
            let cur_round = self.bbr.round_count;
            self.bbr.max_bw = self.bbr.bw_samples[..n_rounds]
                .iter()
                .filter(|s| s.bw > 0 && cur_round.saturating_sub(s.round) < n_rounds as u64)
                .map(|s| s.bw)
                .max()
                .unwrap_or(bw_sample)
                .max(bw_sample);
        }
        self.bbr.delivered_ms = now;

        // Min RTT filter
        if let Some(rtt) = rtt_ms {
            if rtt < self.bbr.min_rtt_ms {
                self.bbr.min_rtt_ms       = rtt;
                self.bbr.min_rtt_stamp_ms = now;
            }
        }

        // Update cwnd
        let (_, cwnd_gain) = self.bbr_gains();
        let bdp = if self.bbr.min_rtt_ms < u64::MAX {
            self.bbr.max_bw * self.bbr.min_rtt_ms / 1_000 // bytes
        } else {
            self.cfg.mss as u64 * self.cfg.initial_cwnd_pkts as u64
        };
        let four_mss      = 4 * self.cfg.mss as u32;
        let cwnd_target   = cwnd_gain.apply(bdp) as u32 + four_mss;
        let new_cwnd      = self.bbr.cwnd.saturating_add(acked_bytes as u32);
        self.bbr.cwnd     = new_cwnd.min(cwnd_target).max(four_mss);

        // Phase transitions
        self.bbr_phase_update(now);
    }

    fn bbr_phase_update(&mut self, now: u64) {
        match self.bbr.phase {
            BbrPhase::Startup => {
                // Exit STARTUP if pipe filled (BW not growing for 3 rounds)
                if !self.bbr.filled_pipe {
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
                    // Loss-based exit
                    if self.bbr.acked_bytes_round > 0 {
                        let loss_rate = self.bbr.loss_bytes_round * 100 / self.bbr.acked_bytes_round;
                        if loss_rate > 2 {
                            self.bbr.filled_pipe = true;
                        }
                    }
                }
                if self.bbr.filled_pipe {
                    self.bbr.phase = BbrPhase::Drain;
                }
            }
            BbrPhase::Drain => {
                let bytes_in_flight = (self.snd_nxt - self.snd_una) as u64;
                let bdp = if self.bbr.min_rtt_ms < u64::MAX && self.bbr.max_bw > 0 {
                    self.bbr.max_bw * self.bbr.min_rtt_ms / 1_000
                } else { 0 };
                if bytes_in_flight <= bdp.max(1) {
                    self.bbr.phase         = BbrPhase::ProbeBw;
                    self.bbr.probe_bw_in_up = true;
                    self.bbr.cycle_stamp_ms = now;
                    // Reset inflight bounds
                    self.bbr.bw_lo       = u64::MAX;
                    self.bbr.inflight_lo = u32::MAX;
                    self.bbr.inflight_hi = u32::MAX;
                }
            }
            BbrPhase::ProbeBw => {
                // Enter PROBE_RTT periodically
                if self.cfg.bbr_probe_rtt_interval_ms > 0
                    && now.saturating_sub(self.bbr.min_rtt_stamp_ms) > self.cfg.bbr_probe_rtt_interval_ms
                    && self.bbr.probe_rtt_done_ms == 0
                {
                    self.bbr.prior_cwnd        = self.bbr.cwnd;
                    self.bbr.cwnd              = (4 * self.cfg.mss as u32).max(self.bbr.prior_cwnd / 4);
                    self.bbr.probe_rtt_done_ms = now + self.cfg.bbr_probe_rtt_duration_ms;
                    self.bbr.phase             = BbrPhase::ProbeRtt;
                    self.bbr.last_probe_rtt_ms = now;
                    return;
                }
                // Cycle PROBE_UP → PROBE_DOWN based on round count
                if self.bbr.probe_bw_in_up {
                    // Stay UP for one round then drain
                    if self.bbr.round_count > 0
                        && now.saturating_sub(self.bbr.cycle_stamp_ms) >= self.srtt_ms.max(1)
                    {
                        self.bbr.probe_bw_in_up = false;
                        self.bbr.cycle_stamp_ms = now;
                    }
                } else {
                    // Drain until in-flight ≤ BDP, then cruise
                    let bytes_in_flight = (self.snd_nxt - self.snd_una) as u64;
                    let bdp = if self.bbr.min_rtt_ms < u64::MAX && self.bbr.max_bw > 0 {
                        self.bbr.max_bw * self.bbr.min_rtt_ms / 1_000
                    } else { 0 };
                    if bytes_in_flight <= bdp.max(1) {
                        self.bbr.probe_bw_in_up = true;
                        self.bbr.cycle_stamp_ms = now;
                        // Reset loss bounds for new UP phase
                        self.bbr.bw_lo       = u64::MAX;
                        self.bbr.inflight_lo = u32::MAX;
                    }
                }
            }
            BbrPhase::ProbeRtt => {
                if self.bbr.probe_rtt_done_ms > 0 && now >= self.bbr.probe_rtt_done_ms {
                    self.bbr.probe_rtt_done_ms = 0;
                    self.bbr.cwnd              = self.bbr.prior_cwnd;
                    self.bbr.phase             = BbrPhase::ProbeBw;
                    self.bbr.probe_bw_in_up    = true;
                    self.bbr.cycle_stamp_ms    = now;
                }
            }
        }
    }

    fn bbr_on_loss(&mut self, lost_bytes: u64) {
        self.bbr.loss_bytes_round += lost_bytes;
        // Loss signal: reduce bw_lo and inflight_lo
        if self.bbr.acked_bytes_round > 0 {
            let loss_rate = self.bbr.loss_bytes_round * 100
                / self.bbr.acked_bytes_round.max(1);
            if loss_rate > 2 {
                if self.bbr.max_bw > 0 {
                    let new_lo = self.bbr.max_bw / 2;
                    if new_lo < self.bbr.bw_lo { self.bbr.bw_lo = new_lo; }
                }
                let new_inf = self.bbr.cwnd / 2;
                if new_inf < self.bbr.inflight_lo { self.bbr.inflight_lo = new_inf; }
                // Also reduce cwnd so it tracks inflight_lo strictly; prevents
                // cwnd from sitting above inflight_lo and growing again before
                // the bounds are cleared (BBRv3 §4.5).
                let floor = (4 * self.cfg.mss as u32).max(self.bbr.inflight_lo);
                if self.bbr.cwnd > floor { self.bbr.cwnd = floor; }
            }
        }
    }

    // ── Core ACK processing ──────────────────────────────────────────────────

    fn on_ack(&mut self, new_ack: SeqNum, opts: &ParsedOpts) {
        let now          = timers::now_ms();
        let mut acked    = 0u64;
        let mut rtt_sample: Option<u64> = None;
        let mut min_dtime: Option<u64>  = None;
        let old_snd_una  = self.snd_una;

        // Only process if ack advances snd_una
        if !seq_gt(new_ack, self.snd_una) { return; }
        self.dupack_count = 0; // belt-and-braces: any advancing ACK resets the counter

        // 1. Remove cumulatively ACKed segments and measure RTT
        let mut i = 0;
        while i < self.unacked.len() {
            let seg = &self.unacked[i];
            if seq_le(seg.end_seq, new_ack) {
                let bytes = seg.data.len() as u64
                    + if !(seg.flags & (TcpFlags::SYN | TcpFlags::FIN)).is_empty() { 1 } else { 0 };
                acked += bytes;
                // Karn's: RTT only from non-retransmitted segments
                if seg.retransmits == 0 && rtt_sample.is_none() {
                    rtt_sample = Some(now.saturating_sub(seg.first_sent_ms));
                }
                if seg.dtime_at_send > 0
                    && min_dtime.is_none_or(|t| seg.dtime_at_send < t)
                {
                    min_dtime = Some(seg.dtime_at_send);
                }
                // RACK: update rack_end_seq/xmit_ms from ACKed segment
                if seq_gt(seg.end_seq, self.rack_end_seq) {
                    self.rack_end_seq  = seg.end_seq;
                    self.rack_xmit_ms  = seg.last_sent_ms;
                }
                self.unacked.remove(i);
            } else {
                i += 1;
            }
        }

        // 2. Mark SACK-covered segments
        for k in 0..opts.sack_count as usize {
            if let Some((left, right)) = opts.sack_blocks[k] {
                let (left, right) = (SeqNum::new(left), SeqNum::new(right));
                for seg in &mut self.unacked {
                    if !seg.sacked && seq_ge(seg.seq, left) && seq_le(seg.end_seq, right) {
                        seg.sacked = true;
                        // Also update RACK from SACK
                        if seq_gt(seg.end_seq, self.rack_end_seq) {
                            self.rack_end_seq = seg.end_seq;
                            self.rack_xmit_ms = seg.last_sent_ms;
                        }
                    }
                }
            }
        }

        // 3. Advance snd_una
        self.snd_una = new_ack;
        let _ = old_snd_una;

        // Keep-alive: reset probe state on any ACK progress
        self.last_recv_ms     = now;
        self.keepalive_probes = 0;
        if self.cfg.keepalive_idle_ms > 0 {
            self.keepalive_deadline_ms = now + self.cfg.keepalive_idle_ms;
        }

        // TS-based RTT (RFC 7323 §4.3): override Karn's sample — TS is Karn-immune
        if self.ts_enabled {
            if let Some(ecr) = opts.ts_ecr {
                if ecr != 0 {
                    let ts_rtt = (timers::now_ms() as u32).wrapping_sub(ecr) as u64;
                    rtt_sample = Some(ts_rtt);
                }
            }
        }

        // 4. RFC 6298 RTT/RTO update
        if let Some(rtt) = rtt_sample {
            if self.srtt_ms == 0 {
                self.srtt_ms   = rtt;
                self.rttvar_ms = rtt / 2;
            } else {
                let diff       = rtt.abs_diff(self.srtt_ms);
                self.rttvar_ms = self.rttvar_ms - self.rttvar_ms / 4 + diff / 4;
                self.srtt_ms   = self.srtt_ms   - self.srtt_ms   / 8 + rtt / 8;
            }
            self.rto_ms = (self.srtt_ms + 4 * self.rttvar_ms)
                .max(self.cfg.rto_min_ms)
                .min(self.cfg.rto_max_ms);
        }

        // 5. BBRv3 bandwidth update
        // Override delivered_ms if this is the first real delivery
        if self.bbr.delivered_ms == 0 && acked > 0 {
            self.bbr.delivered_ms = min_dtime.unwrap_or(now);
        }
        self.bbr_on_ack(acked, rtt_sample, now);

        // 6. RACK loss detection
        // Detect D-SACK (RFC 2883): first SACK block covers data below snd_una
        // → a previously retransmitted segment was re-delivered → spurious
        // retransmit due to reordering → widen the adaptive reorder window.
        if opts.sack_count > 0 {
            if let Some((left, _)) = opts.sack_blocks[0] {
                if seq_lt(SeqNum::new(left), self.snd_una) {
                    let inc = (self.srtt_ms / 4).max(1);
                    self.rack_reo_wnd_ms =
                        (self.rack_reo_wnd_ms + inc).min(self.srtt_ms);
                }
            }
        }
        // Decay rack_reo_wnd_ms on each ACK round (×7/8 per round).
        self.rack_reo_wnd_ms =
            self.rack_reo_wnd_ms.saturating_sub(self.rack_reo_wnd_ms / 8 + 1);

        let rack_rtt       = self.srtt_ms.max(1);
        let reorder_window = (rack_rtt / 4).max(1) + self.rack_reo_wnd_ms;
        // Collect segments to retransmit to avoid borrow conflict
        let mut retx: Vec<(SeqNum, TcpFlags, Vec<u8>)> = Vec::new();
        for seg in &self.unacked {
            if !seg.sacked
                && seq_le(seg.end_seq, self.rack_end_seq)
                && now >= seg.last_sent_ms + rack_rtt + reorder_window
            {
                retx.push((seg.seq, seg.flags, seg.data.clone()));
            }
        }
        for (seq, flags, data) in retx {
            // Update the segment's retransmit metadata
            for s in &mut self.unacked {
                if s.seq == seq {
                    s.retransmits += 1;
                    s.last_sent_ms = now;
                }
            }
            self.bbr_on_loss(data.len() as u64 + if !(flags & (TcpFlags::SYN | TcpFlags::FIN)).is_empty() { 1 } else { 0 });
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
            let _ = self.send_segment(seq, flags, &data, opts_slice);
        }

        // 7. Timer management
        if self.unacked.is_empty() {
            self.rto_deadline_ms = 0;
            self.tlp_deadline_ms = 0;
            self.rto_count       = 0;
        } else {
            // Reset RTO (fresh ACK progress)
            self.rto_deadline_ms = now + self.rto_ms;
            self.rto_count       = 0;
            // Arm TLP if not set
            if self.tlp_deadline_ms == 0 && self.srtt_ms > 0 {
                self.tlp_deadline_ms = now + 2 * self.srtt_ms;
            }
        }
    }

    // ── Send buffer drain ────────────────────────────────────────────────────

    fn flush_send_buf(&mut self) {
        let now = timers::now_ms();
        loop {
            if self.state != State::Established { break; }
            if self.send_buf.is_empty()         { break; }

            // Pacing gate
            if now < self.pacing_next_ms { break; }

            // Peer receive-window gate (RFC 793 §3.7, RFC 7323 §2.3).
            // snd_wnd_raw is the raw (unscaled) value from the peer's header;
            // left-shift by snd_scale to get the true byte count.
            let peer_wnd = (self.snd_wnd_raw as u32) << self.snd_scale;
            let wnd_limit = self.snd_una + peer_wnd;
            if peer_wnd == 0 || seq_ge(self.snd_nxt, wnd_limit) {
                // Arm persist timer when blocked by zero window
                if self.persist_deadline_ms == 0 && !self.send_buf.is_empty() {
                    self.persist_backoff_ms  = self.rto_ms;
                    self.persist_deadline_ms = now + self.persist_backoff_ms;
                }
                break;
            }
            // Window opened — cancel persist timer
            self.persist_deadline_ms = 0;

            // cwnd gate
            let bytes_in_flight = self.snd_nxt - self.snd_una;
            let limit = self.bbr.cwnd
                .min(self.bbr.inflight_lo)
                .min(self.bbr.inflight_hi);
            if bytes_in_flight >= limit { break; }

            // Both gates: cap chunk at the tighter of cwnd room and window room.
            let wnd_room   = (wnd_limit - self.snd_nxt) as usize;
            let available  = ((limit - bytes_in_flight) as usize).min(wnd_room);
            let chunk_len  = (self.peer_mss as usize)
                .min(self.send_buf.len())
                .min(available);
            if chunk_len == 0 { break; }

            // Extract chunk before calling &mut self methods.
            let chunk: Vec<u8> = self.send_buf.drain(..chunk_len).collect();
            let seg_seq        = self.snd_nxt;

            // Send (include Timestamps option when negotiated)
            let ts_arr;
            let ts_slice: &[u8] = if self.ts_enabled {
                ts_arr = self.ts_opt(); &ts_arr
            } else { &[] };
            if self.send_segment(seg_seq, TcpFlags::PSH | TcpFlags::ACK, &chunk, ts_slice).is_err() {
                // On TX error, put bytes back and give up.
                let mut tmp = chunk;
                tmp.append(&mut self.send_buf);
                self.send_buf = tmp;
                break;
            }

            // Record in retransmit buffer
            let seg_end = seg_seq + chunk.len() as u32;
            self.unacked.push(TxSegment {
                seq:              seg_seq,
                end_seq:          seg_end,
                flags:            TcpFlags::PSH | TcpFlags::ACK,
                data:             chunk,
                first_sent_ms:    now,
                last_sent_ms:     now,
                retransmits:      0,
                sacked:           false,
                dtime_at_send:    self.bbr.delivered_ms,
            });
            self.snd_nxt = seg_end;

            // Pacing
            let interval        = self.pacing_interval_ms();
            self.pacing_next_ms = if interval > 0 { now + interval } else { 0 };

            // Arm TLP
            if self.tlp_deadline_ms == 0 && self.srtt_ms > 0 {
                self.tlp_deadline_ms = now + 2 * self.srtt_ms;
            } else if self.tlp_deadline_ms == 0 {
                self.tlp_deadline_ms = now + 10; // fallback 10 ms
            }

            // Arm RTO
            if self.rto_deadline_ms == 0 {
                self.rto_deadline_ms = now + self.rto_ms;
            }
        }
    }

    // ── In-order OOO drain ───────────────────────────────────────────────────

    /// Flush any OOO segments that have become in-order and call on_recv.
    fn drain_ooo(&mut self, eth_src: MacAddr, eth_dst: MacAddr, ip_src: Ipv4Addr, ip_dst: Ipv4Addr) {
        loop {
            let pos = self.rx_ooo.iter().position(|s| s.seq == self.rcv_nxt);
            let Some(pos) = pos else { break };
            let seg = self.rx_ooo.remove(pos);
            self.rcv_nxt += seg.data.len() as u32;
            self.recv_buf.extend_from_slice(&seg.data);
            let on_recv = self.on_recv;
            on_recv(TcpPacket {
                eth_src, eth_dst,
                src: SocketAddrV4::new(ip_src, self.dst.port()),
                dst: SocketAddrV4::new(ip_dst, self.src.port()),
                pdu: &seg.data,
            });
        }
    }

    // ── Segment processing ───────────────────────────────────────────────────

    pub(crate) fn process_segment(&mut self, raw: &[u8]) -> Result<()> {
        let eth = EthHdr::parse(raw)?;
        if eth.ethertype != EtherType::IPV4 { return Ok(()); }
        let ip_buf = eth.payload(raw);
        let ip     = Ipv4Hdr::parse(ip_buf)?;
        if ip.proto != IpProto::TCP || ip.dst != *self.src.ip() { return Ok(()); }
        let tcp_buf = ip.payload(ip_buf);
        let seg     = TcpHdr::parse(tcp_buf)?;
        if seg.dst_port != self.src.port() { return Ok(()); }

        // NOTE: no TCP checksum validation here.  AF_PACKET / TPACKET_V2
        // delivers frames whose checksums have already been verified by the
        // kernel or NIC hardware.  GRO-combined frames carry the *first*
        // segment's checksum which is invalid for the merged payload; validating
        // it would silently discard every GRO super-segment.

        // RST handling (all states that have an established peer)
        if seg.has_flag(TcpFlags::RST) {
            match self.state {
                State::Listen | State::Closed => return Ok(()),
                _ => {}
            }
            // Validate RST is within receive window (use actual advertised window).
            let rcv_wnd   = RECV_BUF_MAX.saturating_sub(self.recv_buf.len() as u32);
            let in_window = seq_ge(seg.seq, self.rcv_nxt)
                && seq_lt(seg.seq, self.rcv_nxt + rcv_wnd);
            if in_window || self.state == State::SynSent {
                self.state      = State::Closed;
                self.last_error = Some(TcpError::Reset);
                let on_error    = self.on_error;
                on_error(TcpError::Reset);
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
                if tsv.wrapping_sub(self.ts_recent) > 0x8000_0000 {
                    // Timestamp is older than ts_recent — PAWS violation.
                    // RFC 7323 §5.2: send a duplicate ACK and discard.
                    let _ = self.send_ctrl(TcpFlags::ACK);
                    return Ok(());
                }
            }
        }

        // Update ts_recent after the PAWS check passes.
        if self.ts_enabled {
            if let Some(tsv) = opts.ts_val { self.ts_recent = tsv; }
        }

        match self.state {
            // ── LISTEN ──────────────────────────────────────────────────────
            State::Listen => {
                if seg.has_flag(TcpFlags::SYN) && !seg.has_flag(TcpFlags::ACK) {
                    self.dst     = SocketAddrV4::new(ip.src, seg.src_port);
                    self.dst_mac = eth.src;
                    self.rcv_nxt  = seg.seq + 1;
                    // Learn peer MSS
                    if let Some(m) = opts.mss { self.peer_mss = m; }
                    self.sack_ok = opts.sack_permitted;
                    // Window scaling: only active if both sides include WS in SYN.
                    // We always send WS in our SYN-ACK; record the peer's shift.
                    // If the peer omitted WS we must advertise an unscaled window.
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
                    let now = timers::now_ms();
                    if self.bbr.delivered_ms == 0 { self.bbr.delivered_ms = now; }
                    self.unacked.push(TxSegment {
                        seq: isn, end_seq: isn + 1,
                        flags: TcpFlags::SYN | TcpFlags::ACK, data: vec![],
                        first_sent_ms: now, last_sent_ms: now,
                        retransmits: 0, sacked: false,
                        dtime_at_send: self.bbr.delivered_ms,
                    });
                    if self.rto_deadline_ms == 0 {
                        self.rto_deadline_ms = now + self.rto_ms;
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
                    if let Some(m) = opts.mss { self.peer_mss = m; }
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
                    if let Some(m) = opts.mss { self.peer_mss = m; }
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
                let rcv_wnd   = RECV_BUF_MAX.saturating_sub(self.recv_buf.len() as u32);
                let in_window = seq_ge(seg.seq, self.rcv_nxt)
                    && seq_lt(seg.seq, self.rcv_nxt + rcv_wnd);
                let is_keepalive = seg.seq == self.rcv_nxt - 1;

                if !in_window && !is_keepalive {
                    // Duplicate or out-of-window: send ACK and discard
                    let _ = self.send_ctrl(TcpFlags::ACK);
                    return Ok(());
                }

                // Payload slice computed here so dupack can check pdu.is_empty().
                let payload_start = seg.hdr_len().min(tcp_buf.len());
                let pdu           = &tcp_buf[payload_start..];

                // Process cumulative ACK; also update the peer's window.
                if seg.has_flag(TcpFlags::ACK) {
                    self.snd_wnd_raw = seg.window;
                    if seq_gt(seg.ack, self.snd_una) {
                        self.dupack_count = 0;
                        self.on_ack(seg.ack, &opts);
                    } else if seg.ack == self.snd_una
                           && self.snd_una != self.snd_nxt
                           && pdu.is_empty()
                    {
                        self.dupack_count = self.dupack_count.saturating_add(1);
                        if self.dupack_count >= 3 {
                            self.dupack_count = 0;
                            let now = timers::now_ms();
                            if let Some(s) = self.unacked.iter().find(|s| !s.sacked) {
                                let (seq, flags, data) = (s.seq, s.flags, s.data.clone());
                                for s in &mut self.unacked {
                                    if s.seq == seq { s.retransmits += 1; s.last_sent_ms = now; }
                                }
                                let opts_arr;
                                let opts_slice: &[u8] = if flags.has(TcpFlags::SYN) {
                                    opts_arr = self.syn_opts(); &opts_arr
                                } else { &[] };
                                let _ = self.send_segment(seq, flags, &data, opts_slice);
                            }
                        }
                    }
                }

                // ECN: detect CE-marked packets (dscp_ecn low bits == 0b11).
                if self.ecn_enabled && (ip.dscp_ecn & 0x03) == 0x03 {
                    self.ecn_ce_pending = true;
                }
                // ECN: react to ECE on incoming ACKs — reduce cwnd as if loss.
                if self.ecn_enabled && seg.has_flag(TcpFlags::ECE) && !seg.has_flag(TcpFlags::SYN) {
                    self.bbr_on_loss(self.cfg.mss as u64);
                    self.ecn_cwr_needed = true;
                }

                // Data / FIN

                if seg.has_flag(TcpFlags::FIN) {
                    // Deliver any data with FIN
                    if !pdu.is_empty() {
                        let advance = pdu.len();
                        if seg.seq == self.rcv_nxt {
                            self.rcv_nxt += advance as u32;
                            self.recv_buf.extend_from_slice(pdu);
                            let on_recv = self.on_recv;
                            let pdu_copy = &tcp_buf[payload_start..]; // borrow raw
                            on_recv(TcpPacket {
                                eth_src: eth.src, eth_dst: eth.dst,
                                src: SocketAddrV4::new(ip.src, seg.src_port),
                                dst: SocketAddrV4::new(ip.dst, seg.dst_port),
                                pdu: pdu_copy,
                            });
                        }
                    }
                    // FIN consumes one sequence number
                    self.rcv_nxt += 1;
                    let _ = self.send_ctrl(TcpFlags::ACK);
                    // Notify peer closed with empty pdu
                    let on_recv = self.on_recv;
                    on_recv(TcpPacket {
                        eth_src: eth.src, eth_dst: eth.dst,
                        src: SocketAddrV4::new(ip.src, seg.src_port),
                        dst: SocketAddrV4::new(ip.dst, seg.dst_port),
                        pdu: &[],
                    });
                    self.state = State::CloseWait;
                    return Ok(());
                }

                if pdu.is_empty() { return Ok(()); }

                if seg.seq == self.rcv_nxt {
                    // In-order segment
                    self.rcv_nxt += pdu.len() as u32;
                    self.recv_buf.extend_from_slice(pdu);
                    // Try to drain OOO queue
                    self.drain_ooo(eth.src, eth.dst, ip.src, ip.dst);
                    // Keep-alive: receiving data resets the idle timer
                    {
                        let now = timers::now_ms();
                        self.last_recv_ms     = now;
                        self.keepalive_probes = 0;
                        if self.cfg.keepalive_idle_ms > 0 {
                            self.keepalive_deadline_ms = now + self.cfg.keepalive_idle_ms;
                        }
                    }
                    // ACK (with SACK if OOO pending)
                    let mut sack_buf = [0u8; 40];
                    let sack_len     = if self.sack_ok { self.build_sack_opts(&mut sack_buf) } else { 0 };
                    let seq = self.snd_nxt;
                    if sack_len > 0 {
                        self.send_segment(seq, TcpFlags::ACK, &[], &sack_buf[..sack_len])?;
                    } else {
                        self.send_ctrl(TcpFlags::ACK)?;
                    }
                    let on_recv = self.on_recv;
                    on_recv(TcpPacket {
                        eth_src: eth.src, eth_dst: eth.dst,
                        src: SocketAddrV4::new(ip.src, seg.src_port),
                        dst: SocketAddrV4::new(ip.dst, seg.dst_port),
                        pdu,
                    });
                } else if seq_gt(seg.seq, self.rcv_nxt) {
                    // Out-of-order: buffer and SACK
                    if self.rx_ooo.len() < self.cfg.rx_ooo_max {
                        // Check for duplicate
                        let dup = self.rx_ooo.iter().any(|s| s.seq == seg.seq);
                        if !dup {
                            self.rx_ooo.push(RxOooSegment { seq: seg.seq, data: pdu.to_vec() });
                            // Sort by seq
                            self.rx_ooo.sort_by(|a, b| {
                                if seq_lt(a.seq, b.seq) { core::cmp::Ordering::Less }
                                else if a.seq == b.seq  { core::cmp::Ordering::Equal }
                                else                    { core::cmp::Ordering::Greater }
                            });
                        }
                    }
                    // Send ACK with SACK
                    let mut sack_buf = [0u8; 40];
                    let sack_len     = if self.sack_ok { self.build_sack_opts(&mut sack_buf) } else { 0 };
                    let seq = self.snd_nxt;
                    if sack_len > 0 {
                        self.send_segment(seq, TcpFlags::ACK, &[], &sack_buf[..sack_len])?;
                    } else {
                        self.send_ctrl(TcpFlags::ACK)?;
                    }
                }
                // else: seq < rcv_nxt (retransmit of already-received data) → ACK only
            }

            // ── FIN_WAIT_1 ──────────────────────────────────────────────────
            State::FinWait1 => {
                let payload_start = seg.hdr_len().min(tcp_buf.len());
                let pdu           = &tcp_buf[payload_start..];

                // Process cumulative ACK (may ACK our FIN or earlier data).
                if seg.has_flag(TcpFlags::ACK) && seq_gt(seg.ack, self.snd_una) {
                    self.on_ack(seg.ack, &opts);
                }

                // Deliver in-order payload data (half-close: peer may still send).
                if !pdu.is_empty() && seg.seq == self.rcv_nxt {
                    self.rcv_nxt += pdu.len() as u32;
                    self.recv_buf.extend_from_slice(pdu);
                    let on_recv = self.on_recv;
                    on_recv(TcpPacket {
                        eth_src: eth.src, eth_dst: eth.dst,
                        src: SocketAddrV4::new(ip.src, seg.src_port),
                        dst: SocketAddrV4::new(ip.dst, seg.dst_port),
                        pdu,
                    });
                }

                // State transition based on whether our FIN was ACKed.
                let fin_acked = seq_ge(self.snd_una, self.snd_nxt);

                if seg.has_flag(TcpFlags::FIN) {
                    self.rcv_nxt += 1;
                    let _ = self.send_ctrl(TcpFlags::ACK);
                    if fin_acked {
                        let now = timers::now_ms();
                        self.rto_deadline_ms = now + TIME_WAIT_MS;
                        self.state = State::TimeWait;
                    } else {
                        self.state = State::Closing;
                    }
                } else if fin_acked {
                    self.state = State::FinWait2;
                }
                if !pdu.is_empty() || seg.has_flag(TcpFlags::FIN) {
                    let _ = self.send_ctrl(TcpFlags::ACK);
                }
            }

            // ── FIN_WAIT_2 ──────────────────────────────────────────────────
            State::FinWait2 => {
                let payload_start = seg.hdr_len().min(tcp_buf.len());
                let pdu           = &tcp_buf[payload_start..];

                // Process ACKs for any remaining retransmit state.
                if seg.has_flag(TcpFlags::ACK) && seq_gt(seg.ack, self.snd_una) {
                    self.on_ack(seg.ack, &opts);
                }

                // Deliver in-order payload data (peer's send direction is open).
                if !pdu.is_empty() && seg.seq == self.rcv_nxt {
                    self.rcv_nxt += pdu.len() as u32;
                    self.recv_buf.extend_from_slice(pdu);
                    let on_recv = self.on_recv;
                    on_recv(TcpPacket {
                        eth_src: eth.src, eth_dst: eth.dst,
                        src: SocketAddrV4::new(ip.src, seg.src_port),
                        dst: SocketAddrV4::new(ip.dst, seg.dst_port),
                        pdu,
                    });
                }

                if seg.has_flag(TcpFlags::FIN) {
                    self.rcv_nxt += 1;
                    let _ = self.send_ctrl(TcpFlags::ACK);
                    let now = timers::now_ms();
                    self.rto_deadline_ms = now + TIME_WAIT_MS;
                    self.state = State::TimeWait;
                } else if !pdu.is_empty() {
                    let _ = self.send_ctrl(TcpFlags::ACK);
                }
            }

            // ── CLOSING ─────────────────────────────────────────────────────
            State::Closing => {
                if seg.has_flag(TcpFlags::ACK) {
                    let now = timers::now_ms();
                    self.rto_deadline_ms = now + TIME_WAIT_MS;
                    self.state = State::TimeWait;
                }
            }

            // ── LAST_ACK ────────────────────────────────────────────────────
            State::LastAck => {
                if seg.has_flag(TcpFlags::ACK) {
                    self.state = State::Closed;
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

            // ── TIME_WAIT / CLOSED ──────────────────────────────────────────
            State::TimeWait | State::Closed => {}
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
        let dst_mac = iface.arp_queue()
            .lookup_and_refresh(nexthop_ip)
            .ok_or(Error::WouldBlock)?;

        let mut s = Self::new_raw(
            iface.tx(), iface.mac(), src, on_recv, on_error,
            cfg,
        );
        s.dst        = dst;
        s.nexthop_ip = nexthop_ip;
        s.dst_mac    = dst_mac;
        s.state      = State::SynSent;
        let syn_opts = s.syn_opts();
        let isn = s.snd_nxt;
        // Advertise ECN capability in SYN (RFC 3168 §6.1.1).
        s.send_ctrl_opts(TcpFlags::SYN | TcpFlags::ECE | TcpFlags::CWR, &syn_opts)?;
        s.snd_nxt += 1;
        let now = timers::now_ms();
        if s.bbr.delivered_ms == 0 { s.bbr.delivered_ms = now; }
        s.unacked.push(TxSegment {
            seq: isn, end_seq: isn + 1,
            flags: TcpFlags::SYN, data: vec![],
            first_sent_ms: now, last_sent_ms: now,
            retransmits: 0, sacked: false,
            dtime_at_send: 0,
        });
        s.rto_deadline_ms = now + s.rto_ms;
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
            iface.tx(), iface.mac(), src, on_recv, on_error,
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
        if new_mss == 0 { return; }
        if new_mss < self.peer_mss { self.peer_mss = new_mss; }
        if new_mss < self.cfg.mss  { self.cfg.mss  = new_mss; }
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /// Drive the state machine: timers, retransmit, send-buffer drain.
    ///
    /// RX is now handled by the uplink's poll loop, which calls
    /// [`process_segment`] directly.
    pub fn poll(&mut self) -> Result<()> {
        let now = timers::now_ms();

        // ── TLP ──
        if self.tlp_deadline_ms != 0 && now >= self.tlp_deadline_ms {
            self.tlp_deadline_ms = 0;
            // Send last unacked segment as probe
            if let Some(seg) = self.unacked.last() {
                let tlp_seq   = seg.seq;
                let tlp_flags = seg.flags;
                let tlp_data  = seg.data.clone();
                let _ = self.send_segment(tlp_seq, tlp_flags, &tlp_data, &[]);
            } else if !self.send_buf.is_empty() {
                // Probe with tail of send_buf
                let probe_len = (self.cfg.mss as usize).min(self.send_buf.len());
                let probe: Vec<u8> = self.send_buf[..probe_len].to_vec();
                let seq = self.snd_nxt;
                let _ = self.send_segment(seq, TcpFlags::PSH | TcpFlags::ACK, &probe, &[]);
            }
        }

        // ── RTO / TIME_WAIT ──
        if self.rto_deadline_ms != 0 && now >= self.rto_deadline_ms {
            if self.state == State::TimeWait {
                self.state           = State::Closed;
                self.rto_deadline_ms = 0;
                return Ok(());
            }
            // Retransmit oldest non-sacked unacked segment
            let oldest = self.unacked.iter().find(|s| !s.sacked).map(|s| {
                (s.seq, s.flags, s.data.clone())
            });
            if let Some((seq, flags, data)) = oldest {
                for s in &mut self.unacked {
                    if s.seq == seq { s.retransmits += 1; s.last_sent_ms = now; }
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
                let _ = self.send_segment(seq, flags, &data, opts_slice);
                self.bbr_on_loss(data.len() as u64);
            }
            self.rto_count += 1;
            if self.rto_count >= self.cfg.max_retransmits {
                self.state      = State::Closed;
                self.last_error = Some(TcpError::Timeout);
                let on_error    = self.on_error;
                on_error(TcpError::Timeout);
                return Ok(());
            }
            self.rto_ms          = (self.rto_ms * 2).min(self.cfg.rto_max_ms);
            self.rto_deadline_ms = now + self.rto_ms;
        }

        // ── Keep-Alive ──
        if self.cfg.keepalive_idle_ms > 0
            && self.keepalive_deadline_ms != 0
            && now >= self.keepalive_deadline_ms
            && self.state == State::Established
        {
            self.keepalive_probes += 1;
            if self.keepalive_probes > self.cfg.keepalive_count {
                self.state      = State::Closed;
                self.last_error = Some(TcpError::Timeout);
                let on_error    = self.on_error;
                on_error(TcpError::Timeout);
                return Ok(());
            }
            let probe_seq = self.snd_una - 1;
            let _ = self.send_segment(probe_seq, TcpFlags::ACK, &[], &[]);
            self.keepalive_deadline_ms = now + self.cfg.keepalive_interval_ms;
        }

        // ── Zero-window persist ──
        if self.persist_deadline_ms != 0
            && now >= self.persist_deadline_ms
            && self.state == State::Established
        {
            // Send a 1-byte window probe (data from the front of send_buf).
            if !self.send_buf.is_empty() {
                let probe_byte = self.send_buf[0];
                let seq = self.snd_nxt;
                let ts_arr;
                let ts_slice: &[u8] = if self.ts_enabled {
                    ts_arr = self.ts_opt(); &ts_arr
                } else { &[] };
                let _ = self.send_segment(seq, TcpFlags::ACK, &[probe_byte], ts_slice);
            }
            // Exponential backoff, capped at rto_max
            self.persist_backoff_ms = (self.persist_backoff_ms * 2)
                .min(self.cfg.rto_max_ms);
            self.persist_deadline_ms = now + self.persist_backoff_ms;
        }

        // ── Drain send buffer ──
        self.flush_send_buf();

        Ok(())
    }

    /// Buffer data for sending.  Only valid in `Established` state.
    ///
    /// Returns [`Error::WouldBlock`] when the send buffer would exceed
    /// [`TcpConfig::send_buf_max`].
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        if self.state != State::Established {
            return Err(Error::NotConnected);
        }
        if self.send_buf.len() + data.len() > self.cfg.send_buf_max {
            return Err(Error::WouldBlock);
        }
        self.send_buf.extend_from_slice(data);
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

    /// Initiate graceful close (sends FIN).
    pub fn close(&mut self) -> Result<()> {
        match self.state {
            State::Established => {
                let fin_seq = self.snd_nxt;
                self.send_ctrl(TcpFlags::FIN | TcpFlags::ACK)?;
                self.snd_nxt += 1;
                self.record_fin(fin_seq);
                self.state = State::FinWait1;
            }
            State::CloseWait => {
                let fin_seq = self.snd_nxt;
                self.send_ctrl(TcpFlags::FIN | TcpFlags::ACK)?;
                self.snd_nxt += 1;
                self.record_fin(fin_seq);
                self.state = State::LastAck;
            }
            _ => {}
        }
        Ok(())
    }

    /// Push a FIN into the retransmit buffer and arm RTO so a lost FIN is
    /// retransmitted.
    fn record_fin(&mut self, fin_seq: SeqNum) {
        let now = timers::now_ms();
        self.unacked.push(TxSegment {
            seq:           fin_seq,
            end_seq:       fin_seq + 1, // FIN occupies 1 sequence byte
            flags:         TcpFlags::FIN | TcpFlags::ACK,
            data:          Vec::new(),
            first_sent_ms: now,
            last_sent_ms:  now,
            retransmits:   0,
            sacked:        false,
            dtime_at_send: self.bbr.delivered_ms,
        });
        if self.rto_deadline_ms == 0 {
            self.rto_deadline_ms = now + self.rto_ms;
        }
    }

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
    let ip      = Ipv4Hdr::parse(ip_buf)?;
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
