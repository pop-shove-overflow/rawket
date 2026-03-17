// Test harness helpers: shared setup for rawket TCP system tests.
#![allow(dead_code)]
//
// Two-level design:
//
//   NetworkPair  — two Networks + Bridge + clocks; all infrastructure.
//                  Used directly for tests that need non-standard socket setup
//                  (e.g. simultaneous open, client-only connections).
//
//   TcpSocketPair — wraps NetworkPair; assumes exactly one TCP socket per side.
//                   Used for the vast majority of tests.
//
// Builder chains:
//   NetworkPair::default()                        — instant link, checksum validation
//   setup_tcp_pair()                              — TcpSocketPair with TcpConfig::default()
//   setup_tcp_pair().profile(link).connect()
//   setup_tcp_pair().tcp_config(cfg).connect()
//   setup_tcp_pair().net_config(NetworkConfig::default).connect()

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use rawket::{
    Clock,
    bridge::{Bridge, Impairment, LinkProfile, PacketSpec, PortDir},
    eth::MacAddr,
    interface::Interface,
    ip::Ipv4Cidr,
    network::{Network, NetworkConfig},
    tcp::{TcpConfig, TcpSocket},
};

use crate::capture::{CaptureBuffer, CapturedFrame, Dir};
use crate::packet::build_tcp_data;

// ── Transfer result types ────────────────────────────────────────────────────

/// Data received by each side during a `transfer` call, keyed by socket
/// index (matching `tcp_a(n)` / `tcp_b(n)`).
pub struct TransferResult {
    pub a: BTreeMap<usize, Vec<u8>>,
    pub b: BTreeMap<usize, Vec<u8>>,
}

// ── NetworkPair ───────────────────────────────────────────────────────────────

/// Two `Network` stacks connected by a `Bridge` with no sockets registered.
///
/// Use directly when a test needs non-standard socket setup — e.g. both sides
/// performing an active open, or a client-only connection with no server.
/// For the common single-socket-per-side case, use [`TcpSocketPair`] instead.
///
/// Fixed addresses:
/// - A: `10.0.0.1/24`, MAC `02:00:00:00:00:01`
/// - B: `10.0.0.2/24`, MAC `02:00:00:00:00:02`
pub struct NetworkPair {
    pub net_a:   Network,
    pub net_b:   Network,
    pub bridge:  Bridge,
    pub port_a:  usize,
    pub port_b:  usize,
    pub clock_a: Clock,
    pub clock_b: Clock,
    pub link:    LinkProfile,
    pub ip_a:    [u8; 4],
    pub ip_b:    [u8; 4],
    pub mac_a:   [u8; 6],
    pub mac_b:   [u8; 6],
    iface_idx_a: usize,
    iface_idx_b: usize,
    net_cfg:     fn() -> NetworkConfig,
}

impl Default for NetworkPair {
    fn default() -> Self {
        setup_network_pair()
    }
}

impl NetworkPair {
    // ── Builder methods ──────────────────────────────────────────────────────

    /// Rebuild with a different link profile.
    pub fn profile(self, link: LinkProfile) -> Self {
        build_network_pair(link, self.net_cfg)
    }

    /// Rebuild with a different network config factory.
    pub fn net_config(self, make_cfg: fn() -> NetworkConfig) -> Self {
        build_network_pair(self.link.clone(), make_cfg)
    }

    // ── Interface accessors ───────────────────────────────────────────────────

    pub fn iface_a(&self) -> &Interface {
        self.net_a.iface(self.iface_idx_a).expect("iface_a")
    }

    pub fn iface_a_mut(&mut self) -> &mut Interface {
        self.net_a.iface_mut(self.iface_idx_a)
    }

    pub fn iface_b(&self) -> &Interface {
        self.net_b.iface(self.iface_idx_b).expect("iface_b")
    }

    pub fn iface_b_mut(&mut self) -> &mut Interface {
        self.net_b.iface_mut(self.iface_idx_b)
    }

    // ── Socket management ─────────────────────────────────────────────────────

    /// Add a TCP socket to A's interface.  Returns the socket index.
    pub fn add_tcp_a(&mut self, sock: TcpSocket) -> usize {
        self.iface_a_mut().add_tcp_socket(sock)
    }

    /// Add a TCP socket to B's interface.  Returns the socket index.
    pub fn add_tcp_b(&mut self, sock: TcpSocket) -> usize {
        self.iface_b_mut().add_tcp_socket(sock)
    }

    /// Immutable reference to the nth TCP socket on A's interface.
    pub fn tcp_a(&self, n: usize) -> &TcpSocket {
        &self.iface_a().tcp_sockets()[n]
    }

    /// Immutable reference to the nth TCP socket on B's interface.
    pub fn tcp_b(&self, n: usize) -> &TcpSocket {
        &self.iface_b().tcp_sockets()[n]
    }

    /// Mutable reference to the nth TCP socket on A's interface.
    pub fn tcp_a_mut(&mut self, n: usize) -> &mut TcpSocket {
        let idx = self.iface_idx_a;
        &mut self.net_a.iface_mut(idx).tcp_sockets_mut()[n]
    }

    /// Mutable reference to the nth TCP socket on B's interface.
    pub fn tcp_b_mut(&mut self, n: usize) -> &mut TcpSocket {
        let idx = self.iface_idx_b;
        &mut self.net_b.iface_mut(idx).tcp_sockets_mut()[n]
    }

    // ── Poll / drain ──────────────────────────────────────────────────────────

    /// Drive net_a's RX loop with a 50 ms timeout.
    pub fn poll_a(&mut self) -> rawket::Result<()> {
        self.net_a.poll_rx_with_timeout(Some(50))
    }

    /// Drive net_b's RX loop with a 50 ms timeout.
    pub fn poll_b(&mut self) -> rawket::Result<()> {
        self.net_b.poll_rx_with_timeout(Some(50))
    }

    /// Drain any already-queued frames on net_a without blocking (timeout=0),
    /// then consume all delivered data from A's TCP recv_bufs (discarded).
    pub fn drain_a(&mut self) {
        self.net_a.poll_rx_with_timeout(Some(0)).ok();
        Self::drain_recv_bufs_into(
            self.net_a.iface_mut(self.iface_idx_a).tcp_sockets_mut(),
            &mut BTreeMap::new(),
        );
    }

    /// Drain any already-queued frames on net_b without blocking (timeout=0),
    /// then consume all delivered data from B's TCP recv_bufs (discarded).
    pub fn drain_b(&mut self) {
        self.net_b.poll_rx_with_timeout(Some(0)).ok();
        Self::drain_recv_bufs_into(
            self.net_b.iface_mut(self.iface_idx_b).tcp_sockets_mut(),
            &mut BTreeMap::new(),
        );
    }

    /// Drain already-queued frames on both sides without blocking (data discarded).
    pub fn drain(&mut self) { self.drain_a(); self.drain_b(); }

    /// Consume all pending recv_buf data from each socket, appending to the map.
    fn drain_recv_bufs_into(sockets: &mut [TcpSocket], out: &mut BTreeMap<usize, Vec<u8>>) {
        let mut scratch = [0u8; 65536];
        for (i, sock) in sockets.iter_mut().enumerate() {
            while let Some(n) = sock.recv(&mut scratch) {
                out.entry(i).or_default().extend_from_slice(&scratch[..n]);
            }
        }
    }

    // ── Impairments ───────────────────────────────────────────────────────────

    // ── Raw impairment API ────────────────────────────────────────────────────

    /// Add an impairment on frames toward B (A's egress).
    pub fn add_impairment_to_b(&self, imp: Impairment) {
        self.bridge.add_impairment(self.port_a, PortDir::Ingress, imp);
    }

    /// Add an impairment on frames toward A (B's egress).
    pub fn add_impairment_to_a(&self, imp: Impairment) {
        self.bridge.add_impairment(self.port_b, PortDir::Ingress, imp);
    }

    /// Remove all impairments on frames toward B.
    pub fn clear_impairments_to_b(&self) { self.bridge.clear_impairments(self.port_a); }

    /// Remove all impairments on frames toward A.
    pub fn clear_impairments_to_a(&self) { self.bridge.clear_impairments(self.port_b); }

    /// Remove all impairments in both directions.
    pub fn clear_impairments(&self) {
        self.bridge.clear_impairments(self.port_a);
        self.bridge.clear_impairments(self.port_b);
    }

    // ── Loss shortcuts ───────────────────────────────────────────────────────

    /// Add probabilistic loss on frames toward B.
    pub fn loss_to_b(&self, rate: f64) {
        self.add_impairment_to_b(Impairment::loss(rate));
    }

    /// Add probabilistic loss on frames toward A.
    pub fn loss_to_a(&self, rate: f64) {
        self.add_impairment_to_a(Impairment::loss(rate));
    }

    /// Add probabilistic loss in both directions.
    pub fn loss_both(&self, rate: f64) {
        self.loss_to_b(rate);
        self.loss_to_a(rate);
    }

    // ── Congestion shortcuts ──────────────────────────────────────────────────

    /// Add probabilistic CE marking on frames toward B.
    pub fn congestion_to_b(&self, rate: f64) {
        self.add_impairment_to_b(Impairment::congestion(rate));
    }

    /// Add probabilistic CE marking on frames toward A.
    pub fn congestion_to_a(&self, rate: f64) {
        self.add_impairment_to_a(Impairment::congestion(rate));
    }

    // ── Drop shortcuts ───────────────────────────────────────────────────────

    /// Drop all TCP data frames toward B.
    pub fn drop_data_to_b(&self) {
        self.add_impairment_to_b(Impairment::Drop(
            PacketSpec::matching(rawket::filter::tcp::has_data()),
        ));
    }

    /// Drop all TCP data frames toward A.
    pub fn drop_data_to_a(&self) {
        self.add_impairment_to_a(Impairment::Drop(
            PacketSpec::matching(rawket::filter::tcp::has_data()),
        ));
    }

    /// Drop the next TCP data frame toward B.
    pub fn drop_next_data_to_b(&self) {
        self.add_impairment_to_b(Impairment::Drop(
            PacketSpec::nth_matching(1, rawket::filter::tcp::has_data()),
        ));
    }

    /// Drop the next TCP data frame toward A.
    pub fn drop_next_data_to_a(&self) {
        self.add_impairment_to_a(Impairment::Drop(
            PacketSpec::nth_matching(1, rawket::filter::tcp::has_data()),
        ));
    }

    /// Drop the Nth TCP data frame toward B.
    pub fn drop_nth_data_to_b(&self, n: usize) {
        self.add_impairment_to_b(Impairment::Drop(
            PacketSpec::nth_matching(n, rawket::filter::tcp::has_data()),
        ));
    }

    /// Drop the Nth TCP data frame toward A.
    pub fn drop_nth_data_to_a(&self, n: usize) {
        self.add_impairment_to_a(Impairment::Drop(
            PacketSpec::nth_matching(n, rawket::filter::tcp::has_data()),
        ));
    }

    // ── Blackhole shortcuts ──────────────────────────────────────────────────

    /// Drop all frames toward B (blackhole).
    pub fn blackhole_to_b(&self) {
        self.add_impairment_to_b(Impairment::Drop(PacketSpec::any()));
    }

    /// Drop all frames toward A (blackhole).
    pub fn blackhole_to_a(&self) {
        self.add_impairment_to_a(Impairment::Drop(PacketSpec::any()));
    }

    /// Blackhole both directions.
    pub fn blackhole_both(&self) {
        self.blackhole_to_b();
        self.blackhole_to_a();
    }

    // ── Deprecated aliases (removed per-test as fixups land) ─────────────────

    pub fn add_impairment_a(&self, imp: Impairment) { self.add_impairment_to_b(imp); }
    pub fn add_impairment_b(&self, imp: Impairment) { self.add_impairment_to_a(imp); }
    pub fn clear_impairments_a(&self) { self.clear_impairments_to_b(); }
    pub fn clear_impairments_b(&self) { self.clear_impairments_to_a(); }

    // ── Frame injection ───────────────────────────────────────────────────────

    /// Push a frame directly into the destination's RX queue (dst MAC lookup),
    /// bypassing impairments and delay.  For use when the timeline is stopped.
    pub fn inject_to_a(&self, frame: Vec<u8>) {
        self.bridge.ingress(&frame);
    }

    /// Push a frame directly into the destination's RX queue (dst MAC lookup),
    /// bypassing impairments and delay.  For use when the timeline is stopped.
    pub fn inject_to_b(&self, frame: Vec<u8>) {
        self.bridge.ingress(&frame);
    }

    /// Forward a frame through the bridge (src MAC → ingress port, dst MAC →
    /// egress port).  Respects ingress/egress impairments and link delay.
    pub fn forward(&self, frame: Vec<u8>) {
        self.bridge.forward(&frame);
    }

    // ── Capture ───────────────────────────────────────────────────────────────

    /// Drain and return all frames captured since the last call.  Clears the bridge buffer.
    pub fn drain_captured(&mut self) -> CaptureBuffer {
        let port_a = self.port_a;
        let mut buf = CaptureBuffer::new();
        for f in self.bridge.drain_captured() {
            let dir         = if f.ingress == port_a { Dir::AtoB } else { Dir::BtoA };
            let was_dropped = f.is_dropped();
            buf.push(CapturedFrame { ts_ns: f.ts_ns, dir, raw: f.data, was_dropped });
        }
        buf
    }

    /// Discard all captured frames accumulated since the last drain.
    pub fn clear_capture(&mut self) { let _ = self.bridge.drain_captured(); }

    // ── Clock advance ─────────────────────────────────────────────────────────

    /// Link RTT in milliseconds (sum of A→B and B→A propagation delays).
    pub fn rtt_ms(&self) -> u64 {
        (self.link.a_to_b.latency_ns + self.link.b_to_a.latency_ns) / 1_000_000
    }

    /// Advance both clocks and bridge by `ms` milliseconds, then deliver ready frames.
    pub fn advance_both(&mut self, ms: i64) {
        let ns = ms as u64 * 1_000_000;
        self.clock_a.advance_ms(ms);
        self.clock_b.advance_ms(ms);
        self.bridge.advance(ns);
        self.drain();
    }

    /// Advance both clocks to the *latest* bridge delivery deadline, then poll
    /// both networks.  This delivers an entire batch of serialized frames in
    /// one call — essential on bandwidth-limited links where serialization
    /// delays spread frame deadlines by ~100 µs per MSS-sized segment.
    pub fn drain_flight(&mut self) {
        if let Some(remaining) = self.bridge.last_remaining_ns() {
            self.clock_a.advance_ns(remaining as i64);
            self.clock_b.advance_ns(remaining as i64);
            self.bridge.advance(remaining);
        }
        self.drain();
    }

    /// Compute the smallest frame-level deadline (bridge delivery or TCP socket
    /// timer) and advance both clocks + bridge by that duration.  Does NOT
    /// poll or drain — call `drain()` separately after this.
    ///
    /// Returns `true` if time was advanced, `false` if no deadlines exist.
    pub fn advance_step(&mut self) -> bool {
        let bridge_dur = self.bridge.next_remaining_ns();
        let now_a = self.clock_a.monotonic_ns();
        let now_b = self.clock_b.monotonic_ns();
        let tcp_a_dur = self.net_a.next_frame_deadline_ns()
            .map(|abs| abs.saturating_sub(now_a));
        let tcp_b_dur = self.net_b.next_frame_deadline_ns()
            .map(|abs| abs.saturating_sub(now_b));
        let next = [bridge_dur, tcp_a_dur, tcp_b_dur]
            .into_iter().flatten().min();
        if let Some(dur) = next {
            self.clock_a.advance_ns(dur as i64);
            self.clock_b.advance_ns(dur as i64);
            self.bridge.advance(dur);
            true
        } else {
            false
        }
    }

    /// Run transfers until the closure returns `false` or no deadlines remain.
    ///
    /// Each iteration: poll both sides, drain recv bufs, then call the closure.
    /// The closure receives `&mut NetworkPair` and can:
    /// - Inspect/modify sockets (send data, check BBR state)
    /// - Call `drain_captured()` to examine frames from this iteration
    /// - Return `true` to continue or `false` to stop
    pub fn transfer_while(
        &mut self,
        mut f: impl FnMut(&mut Self) -> bool,
    ) -> TransferResult {
        let mut result = TransferResult { a: BTreeMap::new(), b: BTreeMap::new() };
        let mut zero_dur_count: u32 = 0;
        loop {
            self.net_a.poll_rx_with_timeout(Some(0)).ok();
            self.net_b.poll_rx_with_timeout(Some(0)).ok();
            Self::drain_recv_bufs_into(
                self.net_a.iface_mut(self.iface_idx_a).tcp_sockets_mut(),
                &mut result.a,
            );
            Self::drain_recv_bufs_into(
                self.net_b.iface_mut(self.iface_idx_b).tcp_sockets_mut(),
                &mut result.b,
            );
            if !f(self) {
                break;
            }
            // Flush any data the closure added to send_bufs so that
            // advance_step sees bridge delivery deadlines, not stale
            // pacing deadlines for unsent data.
            self.net_a.poll_rx_with_timeout(Some(0)).ok();
            self.net_b.poll_rx_with_timeout(Some(0)).ok();
            // Check for dur=0 spin before advancing.
            let bridge_dur = self.bridge.next_remaining_ns();
            let now_a = self.clock_a.monotonic_ns();
            let now_b = self.clock_b.monotonic_ns();
            let tcp_a_dur = self.net_a.next_frame_deadline_ns()
                .map(|abs| abs.saturating_sub(now_a));
            let tcp_b_dur = self.net_b.next_frame_deadline_ns()
                .map(|abs| abs.saturating_sub(now_b));
            let next = [bridge_dur, tcp_a_dur, tcp_b_dur]
                .into_iter().flatten().min();
            if next == Some(0) {
                zero_dur_count += 1;
                if zero_dur_count > 100 {
                    let a_abs = self.net_a.next_frame_deadline_ns();
                    let b_abs = self.net_b.next_frame_deadline_ns();
                    let mut diag = format!(
                        "transfer_while: 100 consecutive dur=0 spins — stuck timer\n\
                         now_a={now_a} now_b={now_b}\n\
                         tcp_a_deadline={a_abs:?} tcp_b_deadline={b_abs:?}\n\
                         bridge_remaining={bridge_dur:?}\n"
                    );
                    if let Some(iface) = self.net_a.iface(self.iface_idx_a) {
                        for (idx, sock) in iface.tcp_sockets().iter().enumerate() {
                            let ts = sock.timer_state();
                            let st = sock.state;
                            use std::fmt::Write;
                            let _ = write!(diag,
                                "tcp_a[{idx}]: state={st:?} timers={ts:?} snd_una={} snd_nxt={} bif={}\n",
                                sock.snd_una(), sock.snd_nxt(), sock.bytes_in_flight()
                            );
                        }
                    }
                    if let Some(iface) = self.net_b.iface(self.iface_idx_b) {
                        for (idx, sock) in iface.tcp_sockets().iter().enumerate() {
                            let ts = sock.timer_state();
                            let st = sock.state;
                            use std::fmt::Write;
                            let _ = write!(diag,
                                "tcp_b[{idx}]: state={st:?} timers={ts:?} snd_una={} snd_nxt={} bif={}\n",
                                sock.snd_una(), sock.snd_nxt(), sock.bytes_in_flight()
                            );
                        }
                    }
                    panic!("{diag}");
                }
            } else {
                zero_dur_count = 0;
            }
            if !self.advance_step() {
                break;
            }
        }
        result
    }

    /// Run all in-flight transfers to completion by looping drain + advance_step,
    /// accumulating all received data per-socket per-side.
    ///
    /// The initial drain processes any frames already queued (e.g. from
    /// injection on an instant link) before checking deadlines.
    pub fn transfer(&mut self) -> TransferResult {
        self.transfer_while(|_| true)
    }

    /// Poll both sides once to process queued frames (bridge deliveries,
    /// injected frames, expired timers).  Does NOT advance time.
    pub fn transfer_one(&mut self) {
        self.net_a.poll_rx_with_timeout(Some(0)).ok();
        self.net_b.poll_rx_with_timeout(Some(0)).ok();
    }

    /// Freeze both clocks for deterministic timer testing.
    pub fn pause_both(&self) { self.clock_a.pause(); self.clock_b.pause(); }

    /// Resume both clocks from a paused state.
    pub fn resume_both(&self) { self.clock_a.resume(); self.clock_b.resume(); }
}

// ── Timestamp patching ───────────────────────────────────────────────────────

/// If `frame` is a TCP segment with a Timestamps option whose TSval is 0,
/// Prepare an injected frame: patch zeroed timestamps and compute the
/// snd_nxt advance needed to cover any data payload.  Returns the
/// seq + payload_len value to pass to `advance_snd_nxt_to`, or `None`
/// if no advance is needed.  A single parse handles both tasks.
fn prepare_injected_frame(
    frame: &mut Vec<u8>,
    sender_clock: &Clock,
    sender_ts_recent: u32,
) -> Option<u32> {
    use etherparse::{SlicedPacket, TransportSlice, TcpOptionElement};

    // Parse in a separate scope so the immutable borrow is dropped before mutation.
    let (ts_offset, snd_nxt_advance) = {
        let Ok(parsed) = SlicedPacket::from_ethernet(frame) else { return None };
        let Some(TransportSlice::Tcp(tcp)) = parsed.transport else { return None };

        // Compute snd_nxt advance from seq + payload.
        // Payload = total TCP segment length minus TCP header length.
        let tcp_total = tcp.slice().len() as u32;
        let tcp_hdr = (tcp.data_offset() as u32) * 4;
        let payload_len = tcp_total.saturating_sub(tcp_hdr);
        let advance = if payload_len > 0 {
            Some(tcp.sequence_number().wrapping_add(payload_len))
        } else {
            None
        };

        // Don't patch SYN or RST timestamps.
        if tcp.syn() || tcp.rst() { return advance; }

        // Find the Timestamps option; only patch if TSval is zero.
        let mut offset = None;
        for opt in tcp.options_iterator() {
            if let Ok(TcpOptionElement::Timestamp(tsval, _)) = opt {
                if tsval == 0 {
                    let opts = tcp.options();
                    let opts_base = opts.as_ptr() as usize - frame.as_ptr() as usize;
                    let mut i = 0;
                    while i < opts.len() {
                        match opts[i] {
                            0 => break,
                            1 => { i += 1; }
                            8 if i + 1 < opts.len() && opts[i + 1] == 10 => {
                                offset = Some(opts_base + i + 2);
                                break;
                            }
                            _ => {
                                if i + 1 < opts.len() {
                                    i += opts[i + 1] as usize;
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                }
                break;
            }
        }
        (offset, advance)
    };

    if let Some(off) = ts_offset {
        let ts_val = sender_clock.monotonic_ms() as u32;

        frame[off..off + 4].copy_from_slice(&ts_val.to_be_bytes());
        frame[off + 4..off + 8].copy_from_slice(&sender_ts_recent.to_be_bytes());

        let old_csum = u16::from_be_bytes([frame[50], frame[51]]);
        let mut acc: u32 = (!old_csum) as u32;
        for w in frame[off..off + 8].chunks(2) {
            acc += u16::from_be_bytes([w[0], w[1]]) as u32;
        }
        while acc > 0xFFFF { acc = (acc & 0xFFFF) + (acc >> 16); }
        let new_csum = !(acc as u16);
        frame[50] = (new_csum >> 8) as u8;
        frame[51] = new_csum as u8;
    }
    snd_nxt_advance
}

// ── TcpSocketPair ─────────────────────────────────────────────────────────────

/// A [`NetworkPair`] with exactly one TCP socket per side, connected via the
/// standard 3-way handshake.
///
/// All [`NetworkPair`] methods are available via `Deref`.
///
/// ```ignore
/// setup_tcp_pair().connect()
/// setup_tcp_pair().profile(LinkProfile::wan()).connect()
/// setup_tcp_pair().tcp_config(keepalive_cfg()).connect()
/// setup_tcp_pair().net_config(NetworkConfig::default).connect()
/// ```
pub struct TcpSocketPair {
    pub net: NetworkPair,
    pub tcp_cfg: TcpConfig,
}

impl std::ops::Deref for TcpSocketPair {
    type Target = NetworkPair;
    fn deref(&self) -> &NetworkPair { &self.net }
}

impl std::ops::DerefMut for TcpSocketPair {
    fn deref_mut(&mut self) -> &mut NetworkPair { &mut self.net }
}

impl Default for TcpSocketPair {
    fn default() -> Self { setup_tcp_pair() }
}

impl TcpSocketPair {
    // ── Socket accessors ──────────────────────────────────────────────────────

    /// Immutable reference to the client (A-side) TCP socket.
    pub fn tcp_a(&self) -> &TcpSocket { self.net.tcp_a(0) }

    /// Immutable reference to the server (B-side) TCP socket.
    pub fn tcp_b(&self) -> &TcpSocket { self.net.tcp_b(0) }

    /// Mutable reference to the client (A-side) TCP socket.
    pub fn tcp_a_mut(&mut self) -> &mut TcpSocket { self.net.tcp_a_mut(0) }

    /// Mutable reference to the server (B-side) TCP socket.
    pub fn tcp_b_mut(&mut self) -> &mut TcpSocket { self.net.tcp_b_mut(0) }

    // ── Timestamp-patching injection ─────────────────────────────────────────
    //
    // Shadows NetworkPair::inject_to_{a,b}.  If the frame contains a TCP
    // Timestamps option with TSval=0, fill in valid values from the sender's
    // clock and ts_recent.  Frames with non-zero TSval (explicit timestamps),
    // SYN, or RST are left untouched.

    /// Inject a frame into A's RX queue.  Patches zeroed timestamps using
    /// B's clock/ts_recent and advances B's snd_nxt to cover any payload.
    pub fn inject_to_a(&mut self, mut frame: Vec<u8>) {
        let ts_recent = self.net.tcp_b(0).ts_recent();
        let advance = prepare_injected_frame(&mut frame, &self.net.clock_b, ts_recent);
        if let Some(end) = advance {
            self.net.tcp_b_mut(0).advance_snd_nxt_to(end);
        }
        self.net.inject_to_a(frame);
    }

    /// Inject a frame into B's RX queue.  Patches zeroed timestamps using
    /// A's clock/ts_recent and advances A's snd_nxt to cover any payload.
    pub fn inject_to_b(&mut self, mut frame: Vec<u8>) {
        let ts_recent = self.net.tcp_a(0).ts_recent();
        let advance = prepare_injected_frame(&mut frame, &self.net.clock_a, ts_recent);
        if let Some(end) = advance {
            self.net.tcp_a_mut(0).advance_snd_nxt_to(end);
        }
        self.net.inject_to_b(frame);
    }

    // ── Builder ───────────────────────────────────────────────────────────────

    /// Set the TCP config used by `connect()`.  Defaults to [`TcpConfig::default()`].
    pub fn tcp_config(mut self, cfg: TcpConfig) -> Self {
        self.tcp_cfg = cfg;
        self
    }

    /// Rebuild with a different link profile.  Must be called before `connect()`.
    pub fn profile(self, link: LinkProfile) -> Self {
        let tcp_cfg = self.tcp_cfg;
        let net_cfg = self.net.net_cfg;
        TcpSocketPair { net: build_network_pair(link, net_cfg), tcp_cfg }
    }

    /// Rebuild with a different network config factory.  Must be called before `connect()`.
    pub fn net_config(self, make_cfg: fn() -> NetworkConfig) -> Self {
        let tcp_cfg = self.tcp_cfg;
        let link    = self.net.link.clone();
        TcpSocketPair { net: build_network_pair(link, make_cfg), tcp_cfg }
    }

    // ── Transfer ──────────────────────────────────────────────────────────────

    /// Run transfers until the closure returns `false` or no deadlines remain.
    pub fn transfer_while(
        &mut self,
        f: impl FnMut(&mut NetworkPair) -> bool,
    ) -> TransferResult {
        self.net.transfer_while(f)
    }

    /// Run all in-flight transfers to completion, returning received data
    /// per-socket per-side.
    pub fn transfer(&mut self) -> TransferResult {
        self.net.transfer()
    }

    // ── TcpConfig builder forwarders ─────────────────────────────────────────

    pub fn rto_min_ms(mut self, ms: u64) -> Self { self.tcp_cfg.rto_min_ms = ms; self }
    pub fn rto_max_ms(mut self, ms: u64) -> Self { self.tcp_cfg.rto_max_ms = ms; self }
    pub fn max_retransmits(mut self, n: u8) -> Self { self.tcp_cfg.max_retransmits = n; self }
    pub fn time_wait_ms(mut self, ms: u64) -> Self { self.tcp_cfg.time_wait_ms = ms; self }
    pub fn keepalive_idle_ms(mut self, ms: u64) -> Self { self.tcp_cfg.keepalive_idle_ms = ms; self }
    pub fn keepalive_interval_ms(mut self, ms: u64) -> Self { self.tcp_cfg.keepalive_interval_ms = ms; self }
    pub fn keepalive_count(mut self, n: u8) -> Self { self.tcp_cfg.keepalive_count = n; self }
    pub fn recv_buf_max(mut self, n: usize) -> Self { self.tcp_cfg.recv_buf_max = n; self }
    pub fn send_buf_max(mut self, n: usize) -> Self { self.tcp_cfg.send_buf_max = n; self }

    /// Perform the TCP 3-way handshake.  Capture is cleared after the handshake.
    ///
    /// Client: `10.0.0.1:12345` → Server: `10.0.0.2:80`.
    pub fn connect(mut self) -> Self {
        self.do_connect();
        self.net.clear_capture();
        self
    }

    /// Like [`connect`], but returns the handshake frames for option inspection.
    pub fn connect_and_capture(mut self) -> (Self, CaptureBuffer) {
        self.do_connect();
        let cap = self.net.drain_captured();
        (self, cap)
    }

    /// Symmetric close: A initiates FIN, B responds, both exchange FINs.
    ///
    /// Leaves A in `TimeWait` and B in `Closed`.
    pub fn close(&mut self) {
        self.tcp_a_mut().close().ok();
        self.net.drain_a();
        self.net.drain_b();
        self.tcp_b_mut().close().ok();
        self.net.drain_b();
        self.net.drain_a();
        self.net.drain_b();
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    fn add_tcp_a(&mut self, sock: TcpSocket) { self.net.add_tcp_a(sock); }
    fn add_tcp_b(&mut self, sock: TcpSocket) { self.net.add_tcp_b(sock); }

    fn do_connect(&mut self) {
        let cfg = self.tcp_cfg.clone();

        let client = TcpSocket::connect_now(
            self.net.iface_a(),
            "10.0.0.1:12345".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
            Ipv4Addr::from([10, 0, 0, 2]),
            |_| {}, |_| {},
            cfg.clone(),
        ).expect("connect_now");
        self.add_tcp_a(client);

        let server = TcpSocket::accept(
            self.net.iface_b(),
            "10.0.0.2:80".parse().unwrap(),
            |_| {}, |_| {}, cfg,
        ).expect("accept");
        self.add_tcp_b(server);

        // Drive the 3-way handshake to completion.  On a lossy link the SYN or
        // SYN-ACK may be dropped; advancing time lets the client RTO fire and
        // retransmit.  200 iterations × 10 ms = 2 s — enough for default
        // TcpConfig (200 ms RTO) and fast overrides.
        use rawket::tcp::State;
        for _ in 0..200 {
            self.net.drain_flight();
            self.net.drain_a();
            self.net.drain_b();
            if self.tcp_a().state == State::Established
                && self.tcp_b().state == State::Established
            {
                return;
            }
            self.net.advance_both(10);
        }
        panic!(
            "connect timed out: A={:?} B={:?}",
            self.tcp_a().state,
            self.tcp_b().state,
        );
    }
}

// ── Network config ────────────────────────────────────────────────────────────

fn test_network_config() -> NetworkConfig {
    NetworkConfig {
        checksum_validate_ip:  true,
        checksum_validate_tcp: true,
        checksum_validate_udp: true,
        ..Default::default()
    }
}

// ── Frame builders ───────────────────────────────────────────────────────────

/// Build a conformant A→B TCP data frame (timestamps filled in by patcher at injection).
/// Ports: 12345 (client) → 80 (server).
pub fn a_to_b(np: &NetworkPair, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
    crate::packet::build_tcp_data_with_ts(
        np.mac_a, np.mac_b, np.ip_a, np.ip_b, 12345, 80, seq, ack, 0, 0, payload,
    )
}

/// Build a conformant B→A TCP data frame (timestamps filled in by patcher at injection).
/// Ports: 80 (server) → 12345 (client).
pub fn b_to_a(np: &NetworkPair, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
    crate::packet::build_tcp_data_with_ts(
        np.mac_b, np.mac_a, np.ip_b, np.ip_a, 80, 12345, seq, ack, 0, 0, payload,
    )
}

// ── setup_network_pair ────────────────────────────────────────────────────────

/// Build two `Network` stacks wired together via an instant (zero-delay) `Bridge`,
/// with no sockets registered.
pub fn setup_network_pair() -> NetworkPair {
    build_network_pair(LinkProfile::instant(), test_network_config)
}

pub(crate) fn build_network_pair(link: LinkProfile, make_cfg: fn() -> NetworkConfig) -> NetworkPair {
    let mac_a  = MacAddr::from([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let mac_b  = MacAddr::from([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let ip_a   = Ipv4Addr::from([10, 0, 0, 1]);
    let ip_b   = Ipv4Addr::from([10, 0, 0, 2]);
    let subnet = Ipv4Cidr::new(Ipv4Addr::from([10, 0, 0, 0]), 24).unwrap();

    let mut net_a = Network::with_config(make_cfg());
    let mut net_b = Network::with_config(make_cfg());
    let clock_a = net_a.clock_ref();
    let clock_b = net_b.clock_ref();

    // Pause both clocks so real-wall-clock jitter from parallel test load
    // cannot contaminate SRTT, RTTVAR, BBR delivery-rate samples, or timer
    // deadlines.  Tests advance time deterministically via advance_both().
    clock_a.pause();
    clock_b.pause();

    let iface_idx_a = net_a.add_interface().mac(mac_a).finish();
    {
        let iface = net_a.iface_mut(iface_idx_a);
        iface.assign_ip(Ipv4Cidr::new(ip_a, 24).unwrap());
        iface.seed_arp(ip_b, mac_b);
    }
    net_a.route_add(subnet, None);

    let iface_idx_b = net_b.add_interface().mac(mac_b).finish();
    {
        let iface = net_b.iface_mut(iface_idx_b);
        iface.assign_ip(Ipv4Cidr::new(ip_b, 24).unwrap());
        iface.seed_arp(ip_a, mac_a);
    }
    net_b.route_add(subnet, None);

    let bridge = Bridge::new();
    let (port_a, port_b) = bridge.add_link(
        &mut net_a, iface_idx_a,
        &mut net_b, iface_idx_b,
        &link,
    );

    // Pre-seed FDB so ingress() and forward() can resolve MACs before any
    // frames have traversed the bridge (e.g. manual-handshake tests).
    bridge.learn(mac_a.into(), port_a);
    bridge.learn(mac_b.into(), port_b);

    NetworkPair {
        net_a, net_b, bridge, port_a, port_b,
        clock_a, clock_b, link,
        ip_a:        [10, 0, 0, 1],
        ip_b:        [10, 0, 0, 2],
        mac_a:       [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        mac_b:       [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        iface_idx_a, iface_idx_b, net_cfg: make_cfg,
    }
}

// ── setup_tcp_pair ────────────────────────────────────────────────────────────

/// Build a [`TcpSocketPair`] with an instant link and default `TcpConfig`.
/// Chain builder methods before calling `connect()`.
pub fn setup_tcp_pair() -> TcpSocketPair {
    TcpSocketPair {
        net:     setup_network_pair(),
        tcp_cfg: TcpConfig::default(),
    }
}
