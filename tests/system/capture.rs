// Frame capture buffer and parsed TCP frame types.
#![allow(dead_code)]
use etherparse::{LinkSlice, NetSlice, SlicedPacket, TcpOptionElement, TransportSlice};
use rawket::tcp::TcpFlags;

// ── Direction ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir { AtoB, BtoA }

// ── Raw captured frame ────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct CapturedFrame {
    pub ts_ns:       u64,
    pub dir:         Dir,
    pub raw:         Vec<u8>,
    pub was_dropped: bool,
}

// ── Parsed TCP frame ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct ParsedOpts {
    pub mss:            Option<u16>,
    pub window_scale:   Option<u8>,
    pub sack_permitted: bool,
    /// (TSval, TSecr)
    pub timestamps:     Option<(u32, u32)>,
    /// (left, right) absolute sequence numbers
    pub sack_blocks:    Vec<(u32, u32)>,
}

#[derive(Clone, Debug)]
pub struct ParsedTcp {
    pub seq:        u32,
    pub ack:        u32,
    pub flags:      TcpFlags,
    /// Raw (unscaled) receive window
    pub window_raw: u16,
    pub opts:       ParsedOpts,
}

#[derive(Clone, Debug)]
pub struct ParsedFrame {
    pub ts_ns:       u64,
    pub dir:         Dir,
    pub was_dropped: bool,
    /// Source MAC (bytes 6..12 of raw frame)
    pub src_mac:     [u8; 6],
    /// Destination MAC (bytes 0..6)
    pub dst_mac:     [u8; 6],
    /// IPv4 source address
    pub src_ip:      [u8; 4],
    /// IPv4 destination address
    pub dst_ip:      [u8; 4],
    pub ip_ecn:      etherparse::IpEcn,
    pub src_port:    u16,
    pub dst_port:    u16,
    pub tcp:         ParsedTcp,
    pub payload_len: usize,
}

impl ParsedFrame {
    pub fn ts_ms(&self) -> u64 { self.ts_ns / 1_000_000 }

    /// Milliseconds elapsed since `earlier`.  Panics if `self` predates `earlier`.
    pub fn ms_since(&self, earlier: &ParsedFrame) -> u64 {
        (self.ts_ns - earlier.ts_ns) / 1_000_000
    }
}

impl CapturedFrame {
    pub fn ts_ms(&self) -> u64 { self.ts_ns / 1_000_000 }
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse a raw Ethernet frame into a `ParsedFrame`.  Returns `None` for
/// non-TCP, IPv6, or malformed frames.
pub fn parse_frame(ts_ns: u64, dir: Dir, was_dropped: bool, raw: &[u8]) -> Option<ParsedFrame> {
    let sliced = SlicedPacket::from_ethernet(raw).ok()?;

    let eth = match sliced.link? {
        LinkSlice::Ethernet2(e) => e,
        _ => return None,
    };
    let src_mac = eth.source();
    let dst_mac = eth.destination();

    let ipv4 = match sliced.net? {
        NetSlice::Ipv4(ip) => ip,
        _ => return None,
    };
    let ip_hdr = ipv4.header();
    let src_ip = ip_hdr.source();
    let dst_ip = ip_hdr.destination();
    let ip_ecn = ip_hdr.ecn();

    let tcp = match sliced.transport? {
        TransportSlice::Tcp(t) => t,
        _ => return None,
    };

    let src_port    = tcp.source_port();
    let dst_port    = tcp.destination_port();
    let seq         = tcp.sequence_number();
    let ack         = tcp.acknowledgment_number();
    let window_raw  = tcp.window_size();
    let payload_len = tcp.payload().len();

    // Reconstruct rawket TcpFlags from etherparse's individual flag accessors.
    let flags = {
        let mut f = TcpFlags::NONE;
        if tcp.fin() { f |= TcpFlags::FIN; }
        if tcp.syn() { f |= TcpFlags::SYN; }
        if tcp.rst() { f |= TcpFlags::RST; }
        if tcp.psh() { f |= TcpFlags::PSH; }
        if tcp.ack() { f |= TcpFlags::ACK; }
        if tcp.ece() { f |= TcpFlags::ECE; }
        if tcp.cwr() { f |= TcpFlags::CWR; }
        f
    };

    // Parse TCP options via etherparse's typed iterator.
    let mut opts = ParsedOpts::default();
    for opt in tcp.options_iterator() {
        match opt {
            Ok(TcpOptionElement::MaximumSegmentSize(mss)) => {
                opts.mss = Some(mss);
            }
            Ok(TcpOptionElement::WindowScale(ws)) => {
                opts.window_scale = Some(ws);
            }
            Ok(TcpOptionElement::SelectiveAcknowledgementPermitted) => {
                opts.sack_permitted = true;
            }
            Ok(TcpOptionElement::Timestamp(tsval, tsecr)) => {
                opts.timestamps = Some((tsval, tsecr));
            }
            Ok(TcpOptionElement::SelectiveAcknowledgement(first, rest)) => {
                opts.sack_blocks.push(first);
                for b in rest.iter().flatten() {
                    opts.sack_blocks.push(*b);
                }
            }
            _ => {}
        }
    }

    Some(ParsedFrame {
        ts_ns, dir, was_dropped,
        src_mac, dst_mac,
        src_ip, dst_ip,
        ip_ecn,
        src_port, dst_port,
        tcp: ParsedTcp { seq, ack, flags, window_raw, opts },
        payload_len,
    })
}

// ── CaptureBuffer ─────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct CaptureBuffer {
    captured_frames: Vec<CapturedFrame>,
}

impl CaptureBuffer {
    pub fn new() -> Self { Self::default() }

    pub fn push(&mut self, f: CapturedFrame) {
        self.captured_frames.push(f);
    }

    pub fn len(&self) -> usize { self.captured_frames.len() }
    pub fn is_empty(&self) -> bool { self.captured_frames.is_empty() }

    pub fn clear(&mut self) { self.captured_frames.clear(); }

    /// Delivered frames, parsed as TCP.  Frames suppressed by bridge
    /// impairments are excluded.  Non-TCP frames (ARP, ICMP, etc.) are
    /// silently skipped.
    ///
    /// Use [`all_frames`](Self::all_frames) when you also need frames that
    /// were dropped (e.g. to measure RTO retransmit timing against the
    /// original dropped send).
    pub fn frames(&self) -> impl Iterator<Item = ParsedFrame> + '_ {
        self.captured_frames.iter()
            .filter(|f| !f.was_dropped)
            .filter_map(|f| parse_frame(f.ts_ns, f.dir, f.was_dropped, &f.raw))
    }

    /// All frames including those suppressed by bridge impairments, parsed as
    /// TCP.  Non-TCP frames (ARP, ICMP, etc.) are silently skipped.
    ///
    /// Each [`ParsedFrame`] carries `was_dropped`, which is `true` when the
    /// frame entered the bridge on ingress but was suppressed by an impairment
    /// before reaching egress.  Filter on it to separate the two populations:
    ///
    /// ```ignore
    /// cap.all_frames().filter(|f|  f.was_dropped)   // suppressed by impairment
    /// cap.all_frames().filter(|f| !f.was_dropped)   // actually forwarded
    /// ```
    pub fn all_frames(&self) -> impl Iterator<Item = ParsedFrame> + '_ {
        self.captured_frames.iter()
            .filter_map(|f| parse_frame(f.ts_ns, f.dir, f.was_dropped, &f.raw))
    }

    /// Delivered TCP frames.  Shorthand for [`frames`](Self::frames) scoped
    /// to TCP; will filter by protocol once multi-protocol parsing is added.
    pub fn tcp(&self) -> impl Iterator<Item = ParsedFrame> + '_ {
        self.frames()
    }

    /// All TCP frames including those suppressed by bridge impairments.
    /// Shorthand for [`all_frames`](Self::all_frames) scoped to TCP; will
    /// filter by protocol once multi-protocol parsing is added.
    pub fn all_tcp(&self) -> impl Iterator<Item = ParsedFrame> + '_ {
        self.all_frames()
    }

    /// Iterator over raw [`CapturedFrame`]s (all captured frames, including
    /// non-TCP and dropped).  Useful when raw bytes are needed (e.g. for
    /// building ICMP messages from an original data frame).
    pub fn raw(&self) -> impl Iterator<Item = &CapturedFrame> + '_ {
        self.captured_frames.iter()
    }
}

// ── ParsedFrameExt ────────────────────────────────────────────────────────────

/// Extension methods for any iterator of [`ParsedFrame`], allowing flag
/// filters to be chained directly:
///
/// ```ignore
/// cap.tcp().with_tcp_flags(TcpFlags::SYN)
/// cap.all_tcp().with_tcp_flags(TcpFlags::FIN)
/// ```
pub trait ParsedFrameExt: Iterator<Item = ParsedFrame> + Sized {
    /// Retain only frames travelling in the given direction.
    fn direction(self, dir: Dir) -> impl Iterator<Item = ParsedFrame> {
        self.filter(move |f| f.dir == dir)
    }

    /// Retain only frames travelling from A to B.
    fn from_a(self) -> impl Iterator<Item = ParsedFrame> {
        self.direction(Dir::AtoB)
    }

    /// Retain only frames travelling from B to A.
    fn from_b(self) -> impl Iterator<Item = ParsedFrame> {
        self.direction(Dir::BtoA)
    }

    /// Retain only frames suppressed by a bridge impairment (`was_dropped == true`).
    fn dropped(self) -> impl Iterator<Item = ParsedFrame> {
        self.filter(|f| f.was_dropped)
    }

    /// Retain only frames actually forwarded by the bridge (`was_dropped == false`).
    fn delivered(self) -> impl Iterator<Item = ParsedFrame> {
        self.filter(|f| !f.was_dropped)
    }

    /// Retain only frames that carry a TCP payload (`payload_len > 0`).
    fn with_data(self) -> impl Iterator<Item = ParsedFrame> {
        self.filter(|f| f.payload_len > 0)
    }

    /// Retain only frames carrying at least the given flag(s).
    /// Uses `has()` semantics: matches if *any* of the specified bits are set.
    fn with_tcp_flags(self, flags: TcpFlags) -> impl Iterator<Item = ParsedFrame> {
        self.filter(move |f| f.tcp.flags.has(flags))
    }

    /// Retain only frames whose flag set equals `flags` exactly.
    fn with_tcp_flags_exact(self, flags: TcpFlags) -> impl Iterator<Item = ParsedFrame> {
        self.filter(move |f| f.tcp.flags == flags)
    }

    /// Retain only frames that have none of the given flag bits set.
    fn without_tcp_flags(self, flags: TcpFlags) -> impl Iterator<Item = ParsedFrame> {
        self.filter(move |f| !f.tcp.flags.has(flags))
    }
}

impl<I: Iterator<Item = ParsedFrame>> ParsedFrameExt for I {}
