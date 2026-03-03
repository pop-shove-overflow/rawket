/// Top-level network runtime.
///
/// A [`Network`] owns a set of [`Uplink`]s — one per physical interface
/// (ifindex).  Each [`Uplink`] pairs one shared [`EtherLink`] with the
/// [`Interface`]s (Layer-3 virtual NICs) that are multiplexed over it, plus
/// the [`UdpSocket`]s and [`TcpSocket`]s registered on that uplink.
///
/// [`Network::poll_rx`] is the single entry point for inbound traffic: it
/// updates the timer system, blocks in `poll(2)` for the appropriate
/// duration, drains all ready rings, and updates the timer system again.
use core::net::Ipv4Addr;
use crate::{
    arp_cache,
    eth::MacAddr,
    interface::Interface,
    ip::Ipv4Cidr,
    af_packet::{AfPacketSocket, EtherLink, FRAME_SIZE},
    tcp::{TcpConfig, TcpSocket},
    timers::{Timers, now_ms},
    udp::UdpSocket,
    Error, Result,
};
use alloc::{boxed::Box, vec::Vec};

// ── NetworkConfig ─────────────────────────────────────────────────────────────

/// Runtime configuration for the rawket network stack.
///
/// Pass to [`Network::with_config`]; or use [`Network::new`] to accept the
/// defaults.
pub struct NetworkConfig {
    /// Maximum lifetime of an ARP cache entry in milliseconds.
    ///
    /// Entries are inserted when an ARP Reply is received and purged by a
    /// recurring timer after this duration.  Default: 20 000 ms (20 s).
    pub arp_cache_max_age_ms: u64,

    /// How long to wait for missing fragments before discarding a partial
    /// reassembly, in milliseconds.  Default: 30 000 ms (30 s).
    pub ip_frag_timeout_ms: u64,

    /// Maximum bytes that may be held across all in-flight fragment-reassembly
    /// buffers.  When this limit is reached, fragments starting a *new*
    /// reassembly are silently dropped; fragments for already-tracked datagrams
    /// are still accepted.  Default: 65 536 bytes (64 KiB).
    pub ip_frag_mem_limit: usize,

    /// Maximum concurrent reassembly entries per source IP.  Prevents a
    /// single sender from exhausting the global fragment budget.  Default: 4.
    pub ip_frag_per_src_max: usize,

    /// Maximum ARP cache entries per interface.  When full, the oldest entry
    /// (FIFO) is evicted to make room.  Default: 256.
    pub arp_cache_max_entries: usize,

    /// Maximum outbound frames queued per unresolved destination IP.  Frames
    /// beyond this limit are silently dropped.  Default: 4.
    pub arp_queue_max_pending: usize,

    /// Maximum ICMP Unreachable messages sent per second per interface.  0
    /// disables rate limiting (unlimited, e.g. for trusted environments).
    /// Default: 100.
    pub icmp_rate_limit_per_sec: u32,

    // ── TCP / BBRv3 knobs ──────────────────────────────────────────────────

    /// Maximum Segment Size advertised to peers.  Default: 1460.
    pub tcp_mss: u16,

    /// Initial congestion window in packets.  Default: 10.
    pub tcp_initial_cwnd_pkts: u32,

    /// Minimum retransmission timeout in milliseconds.  Default: 200.
    pub tcp_rto_min_ms: u64,

    /// Maximum retransmission timeout in milliseconds.  Default: 60 000.
    pub tcp_rto_max_ms: u64,

    /// Number of consecutive retransmits before declaring a Timeout error.
    /// Default: 15.
    pub tcp_max_retransmits: u8,

    /// BBRv3 bandwidth filter window in RTT rounds.  Default: 10.
    pub tcp_bbr_bw_filter_rounds: u8,

    /// How long (ms) to hold cwnd at the reduced PROBE_RTT level.  Default: 200.
    pub tcp_bbr_probe_rtt_duration_ms: u64,

    /// How frequently (ms) to enter PROBE_RTT to refresh the min-RTT estimate.
    /// Default: 5 000.
    pub tcp_bbr_probe_rtt_interval_ms: u64,

    // ── TCP Keep-Alive ─────────────────────────────────────────────────────

    /// TCP keep-alive idle time in ms (0 = disabled).  Default: 0.
    pub tcp_keepalive_idle_ms: u64,

    /// Interval between keep-alive probes in ms.  Default: 75 000.
    pub tcp_keepalive_interval_ms: u64,

    /// Number of unanswered probes before a Timeout error.  Default: 9.
    pub tcp_keepalive_count: u8,

    /// Maximum bytes buffered in a TCP send buffer.  `send()` returns
    /// `WouldBlock` when adding `data` would exceed this limit.
    /// Default: 1 MiB.
    pub tcp_send_buf_max: usize,

    /// Maximum out-of-order TCP segments buffered per connection.  Segments
    /// beyond this limit are dropped; the sender must retransmit them.  At
    /// most 4 SACK blocks are emitted regardless of this value.  Default: 8.
    pub tcp_rx_ooo_max: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            arp_cache_max_age_ms:          20_000,
            ip_frag_timeout_ms:            30_000,
            ip_frag_mem_limit:             65_536,
            ip_frag_per_src_max:           4,
            arp_cache_max_entries:         256,
            arp_queue_max_pending:         4,
            icmp_rate_limit_per_sec:       100,
            tcp_mss:                       1460,
            tcp_initial_cwnd_pkts:         10,
            tcp_rto_min_ms:                200,
            tcp_rto_max_ms:                60_000,
            tcp_max_retransmits:           15,
            tcp_bbr_bw_filter_rounds:      10,
            tcp_bbr_probe_rtt_duration_ms: 200,
            tcp_bbr_probe_rtt_interval_ms: 5_000,
            tcp_keepalive_idle_ms:         0,
            tcp_keepalive_interval_ms:     75_000,
            tcp_keepalive_count:           9,
            tcp_send_buf_max:              1 << 20,
            tcp_rx_ooo_max:                8,
        }
    }
}

impl NetworkConfig {
    /// Derive a [`TcpConfig`] from the TCP-related fields of this config.
    pub fn tcp_config(&self) -> TcpConfig {
        TcpConfig {
            mss:                       self.tcp_mss,
            initial_cwnd_pkts:         self.tcp_initial_cwnd_pkts,
            rto_min_ms:                self.tcp_rto_min_ms,
            rto_max_ms:                self.tcp_rto_max_ms,
            max_retransmits:           self.tcp_max_retransmits,
            bbr_bw_filter_rounds:      self.tcp_bbr_bw_filter_rounds,
            bbr_probe_rtt_duration_ms: self.tcp_bbr_probe_rtt_duration_ms,
            bbr_probe_rtt_interval_ms: self.tcp_bbr_probe_rtt_interval_ms,
            keepalive_idle_ms:         self.tcp_keepalive_idle_ms,
            keepalive_interval_ms:     self.tcp_keepalive_interval_ms,
            keepalive_count:           self.tcp_keepalive_count,
            send_buf_max:              self.tcp_send_buf_max,
            rx_ooo_max:                self.tcp_rx_ooo_max,
        }
    }
}

// ── Routing table ─────────────────────────────────────────────────────────────

/// A single entry in the per-`Network` routing table.
pub(crate) struct Route {
    pub dst:     Ipv4Cidr,
    /// `None` = on-link (connected route); `Some(gw)` = forward via gateway.
    pub nexthop: Option<Ipv4Addr>,
}

/// Result of a successful [`Network::route_get`] lookup.
#[derive(Clone, Copy)]
pub(crate) struct RouteResult {
    /// Index into `Network::uplinks` — the egress uplink.
    pub intf_idx:   usize,
    /// Source address assigned to the egress interface.
    pub src_ip:     Ipv4Addr,
    /// IP address to resolve via ARP (gateway IP, or `dst_ip` for on-link routes).
    pub nexthop_ip: Ipv4Addr,
}

// ── Uplink ────────────────────────────────────────────────────────────────────

/// Entry in the per-uplink Ethernet-tap table.
#[allow(clippy::type_complexity)]
struct EthEntry {
    id:       usize,
    callback: Box<dyn Fn(&[u8])>,
}

/// One physical uplink: a shared [`EtherLink`], the L3 [`Interface`]s
/// multiplexed over it, and the L4 sockets registered on those interfaces.
pub struct Uplink<L: EtherLink> {
    sock:                    L,
    interfaces:              Vec<Interface>,
    udp_sockets:             Vec<UdpSocket>,
    tcp_sockets:             Vec<TcpSocket>,
    standalone_tcp:          Vec<TcpSocket>,
    arp_cache_max_age_ms:    u64,
    arp_cache_max_entries:   usize,
    arp_queue_max_pending:   usize,
    ip_frag_timeout_ms:      u64,
    ip_frag_mem_limit:       usize,
    ip_frag_per_src_max:     usize,
    icmp_rate_limit_per_sec: u32,
    eth_callbacks:           Vec<EthEntry>,
    next_eth_id:             usize,
}

impl<L: EtherLink> Uplink<L> {
    /// Attach `iface` to this uplink.
    ///
    /// - Registers the interface's MAC in the socket's BPF filter.
    /// - Applies [`NetworkConfig::arp_cache_max_age_ms`] to the interface's
    ///   ARP cache.
    /// - Installs a recurring ARP cache expiry timer.
    pub fn attach(&mut self, mut iface: Interface, timers: &mut Timers) -> Result<()> {
        self.sock.attach_mac(&iface.mac())?;
        iface.set_tx(self.sock.open_tx()?);
        // Apply network-wide ARP settings and install the recurring expiry timer.
        iface.arp_queue().set_max_age_ms(self.arp_cache_max_age_ms);
        iface.arp_queue().set_max_entries(self.arp_cache_max_entries);
        iface.arp_queue().set_max_pending_per_ip(self.arp_queue_max_pending);
        arp_cache::schedule_expiry(iface.arp_queue().clone(), timers);
        // Apply network-wide fragment-reassembly settings and install the
        // periodic purge timer.
        iface.set_frag_config(
            self.ip_frag_timeout_ms,
            self.ip_frag_mem_limit,
            self.ip_frag_per_src_max,
        );
        iface.schedule_frag_purge(timers);
        // Apply ICMP rate limit.
        iface.set_icmp_rate_limit(self.icmp_rate_limit_per_sec);
        self.interfaces.push(iface);
        Ok(())
    }

    /// Remove the interface with the given MAC and unregister it from the
    /// BPF filter.  Returns the interface if found, `None` otherwise.
    ///
    /// Marks the interface's ARP queue as dead, which stops the
    /// self-rescheduling expiry timer and drops all queued outbound frames.
    pub fn detach(&mut self, mac: &MacAddr) -> Result<Option<Interface>> {
        if let Some(idx) = self.interfaces.iter().position(|i| &i.mac() == mac) {
            let iface = self.interfaces.remove(idx);
            iface.arp_queue().mark_dead();
            self.sock.detach_mac(mac)?;
            Ok(Some(iface))
        } else {
            Ok(None)
        }
    }

    /// Register a UDP socket for callback-based delivery via [`Network::poll_rx`].
    pub fn add_udp_socket(&mut self, sock: UdpSocket) {
        self.udp_sockets.push(sock);
    }

    /// Register a TCP socket for callback-based delivery via [`Network::poll_rx`].
    pub fn add_tcp_socket(&mut self, sock: TcpSocket) {
        self.tcp_sockets.push(sock);
    }

    pub fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    pub fn interfaces_mut(&mut self) -> &mut [Interface] {
        &mut self.interfaces
    }

    pub fn udp_sockets(&self) -> &[UdpSocket] {
        &self.udp_sockets
    }

    pub fn udp_sockets_mut(&mut self) -> &mut [UdpSocket] {
        &mut self.udp_sockets
    }

    pub fn tcp_sockets(&self) -> &[TcpSocket] {
        &self.tcp_sockets
    }

    pub fn tcp_sockets_mut(&mut self) -> &mut [TcpSocket] {
        &mut self.tcp_sockets
    }

    pub fn standalone_tcp(&self) -> &[TcpSocket] {
        &self.standalone_tcp
    }

    pub fn standalone_tcp_mut(&mut self) -> &mut [TcpSocket] {
        &mut self.standalone_tcp
    }

    /// Add a standalone TCP socket (from rawket_tcp_connect / rawket_tcp_accept).
    pub fn add_standalone_tcp(&mut self, sock: TcpSocket) {
        self.standalone_tcp.push(sock);
    }

    /// Remove the standalone TCP socket with the given source port.
    pub(crate) fn remove_standalone_tcp(&mut self, src_port: u16) {
        self.standalone_tcp.retain(|s| s.src_port() != src_port);
    }

    /// Remove the UDP socket with the given source port.
    pub(crate) fn remove_udp_socket(&mut self, src_port: u16) {
        self.udp_sockets.retain(|s| s.src_port() != src_port);
    }

    pub(crate) fn socket_mut(&mut self) -> &mut L {
        &mut self.sock
    }

    /// Register a callback invoked for every received Ethernet frame (tap,
    /// not intercept).  Returns an opaque ID for use with
    /// [`remove_eth_callback`].
    pub(crate) fn add_eth_callback(&mut self, cb: impl Fn(&[u8]) + 'static) -> usize {
        let id = self.next_eth_id;
        self.next_eth_id += 1;
        self.eth_callbacks.push(EthEntry { id, callback: Box::new(cb) });
        id
    }

    /// Remove the callback registered with the given `id`.
    pub(crate) fn remove_eth_callback(&mut self, id: usize) {
        self.eth_callbacks.retain(|e| e.id != id);
    }

    /// Transmit a raw Ethernet frame via this uplink's TX ring.
    pub(crate) fn tx_send(&mut self, frame: &[u8]) -> Result<()> {
        self.sock.tx_send(frame)
    }

    /// Replace the MAC on the first attached interface, updating the BPF
    /// filter accordingly.
    pub(crate) fn set_iface_mac(&mut self, new_mac: MacAddr) -> Result<()> {
        let iface = self.interfaces.first_mut().ok_or(Error::InvalidInput)?;
        let old   = iface.mac();
        self.sock.detach_mac(&old)?;
        iface.set_mac(new_mac);
        self.sock.attach_mac(&new_mac)?;
        Ok(())
    }
}

// ── Network ───────────────────────────────────────────────────────────────────

/// Top-level network runtime — owns all uplinks and drives inbound traffic.
pub struct Network<L: EtherLink> {
    uplinks: Vec<Uplink<L>>,
    config:  NetworkConfig,
    timers:  Timers,
    routes:  Vec<Route>,
}

impl Default for Network<AfPacketSocket> {
    fn default() -> Self { Self::new() }
}

impl Network<AfPacketSocket> {
    /// Create a network runtime with default configuration.
    pub fn new() -> Self {
        Self::with_config(NetworkConfig::default())
    }
}

impl<L: EtherLink> Network<L> {
    /// Create a network runtime with the given configuration.
    pub fn with_config(config: NetworkConfig) -> Self {
        Network { uplinks: Vec::new(), config, timers: Timers::new(), routes: Vec::new() }
    }

    /// Register an [`EtherLink`] as an uplink and return a mutable reference
    /// to the new [`Uplink`] so the caller can immediately attach interfaces.
    pub fn add_uplink(&mut self, sock: L) -> &mut Uplink<L> {
        self.uplinks.push(Uplink {
            sock,
            interfaces:              Vec::new(),
            udp_sockets:             Vec::new(),
            tcp_sockets:             Vec::new(),
            standalone_tcp:          Vec::new(),
            arp_cache_max_age_ms:    self.config.arp_cache_max_age_ms,
            arp_cache_max_entries:   self.config.arp_cache_max_entries,
            arp_queue_max_pending:   self.config.arp_queue_max_pending,
            ip_frag_timeout_ms:      self.config.ip_frag_timeout_ms,
            ip_frag_mem_limit:       self.config.ip_frag_mem_limit,
            ip_frag_per_src_max:     self.config.ip_frag_per_src_max,
            icmp_rate_limit_per_sec: self.config.icmp_rate_limit_per_sec,
            eth_callbacks:           Vec::new(),
            next_eth_id:             0,
        });
        self.uplinks.last_mut().unwrap()
    }

    /// Add an uplink and immediately attach one interface to it.
    ///
    /// This is the standard one-step setup for callers that have exactly one
    /// [`Interface`] per [`EtherLink`].  It is equivalent to calling
    /// [`add_uplink`](Self::add_uplink) followed by [`Uplink::attach`], but
    /// without requiring the caller to obtain a `&mut Timers` handle (which
    /// is internal to `Network`).
    ///
    /// Returns the index of the newly created uplink.
    pub fn add_uplink_and_attach(&mut self, sock: L, iface: Interface) -> Result<usize> {
        self.add_uplink(sock);
        let idx = self.uplinks.len() - 1;
        let (uplinks, timers) = self.uplinks_and_timers_mut();
        uplinks[idx].attach(iface, timers)?;
        Ok(idx)
    }

    pub fn uplinks(&self) -> &[Uplink<L>] {
        &self.uplinks
    }

    pub fn uplinks_mut(&mut self) -> &mut [Uplink<L>] {
        &mut self.uplinks
    }

    /// Return disjoint mutable references to the uplinks vec and the timers.
    ///
    /// Used by [`rawket_network_add_intf`](crate::ffi) to call
    /// [`Uplink::attach`] (which needs `&mut Timers`) without triggering a
    /// double-borrow of `Network`.
    pub(crate) fn uplinks_and_timers_mut(&mut self) -> (&mut Vec<Uplink<L>>, &mut Timers) {
        (&mut self.uplinks, &mut self.timers)
    }

    /// Find the uplink index and interface assigned `src_ip`, and return the
    /// network-derived [`TcpConfig`] alongside it.
    ///
    /// Returns `None` if no attached interface has that IP.
    pub(crate) fn find_iface_for_src_ip(
        &self,
        src_ip: Ipv4Addr,
    ) -> Option<(usize, &Interface, TcpConfig)> {
        let cfg = self.config.tcp_config();
        for (idx, uplink) in self.uplinks.iter().enumerate() {
            for iface in &uplink.interfaces {
                if iface.ip().is_some_and(|c| c.addr() == src_ip) {
                    return Some((idx, iface, cfg));
                }
            }
        }
        None
    }

    /// Add or replace a route in the routing table.
    ///
    /// If a route with the same destination CIDR already exists it is updated
    /// in place; otherwise the new route is appended.
    pub fn route_add(&mut self, dst: Ipv4Cidr, nexthop: Option<Ipv4Addr>) {
        if let Some(e) = self.routes.iter_mut().find(|r| r.dst == dst) {
            e.nexthop = nexthop;
        } else {
            self.routes.push(Route { dst, nexthop });
        }
    }

    /// Remove the route matching `dst`, if present.  No-op when absent.
    pub fn route_del(&mut self, dst: Ipv4Cidr) {
        self.routes.retain(|r| r.dst != dst);
    }

    /// Longest-prefix-match lookup for `dst_ip`.
    ///
    /// Returns the nexthop IP to ARP for and the egress interface identified
    /// by the interface whose subnet contains that nexthop.
    pub(crate) fn route_get(&self, dst_ip: Ipv4Addr) -> Option<RouteResult> {
        // Longest-prefix-match: highest prefix_len wins (0.0.0.0/0 is last).
        let route = self.routes
            .iter()
            .filter(|r| r.dst.contains(dst_ip))
            .max_by_key(|r| r.dst.prefix_len())?;

        let nexthop_ip = route.nexthop.unwrap_or(dst_ip);

        // Find the egress interface: the one whose subnet contains nexthop_ip.
        for (idx, uplink) in self.uplinks.iter().enumerate() {
            for iface in &uplink.interfaces {
                if let Some(cidr) = iface.ip() {
                    if cidr.contains(nexthop_ip) {
                        return Some(RouteResult {
                            intf_idx: idx,
                            src_ip: cidr.addr(),
                            nexthop_ip,
                        });
                    }
                }
            }
        }
        None
    }

    /// Return the network-level [`TcpConfig`].
    pub(crate) fn tcp_config(&self) -> TcpConfig {
        self.config.tcp_config()
    }

    /// Dispatch inbound frames and drive the timer system.
    ///
    /// Equivalent to `poll_rx_with_timeout(None)`.
    pub fn poll_rx(&mut self) -> Result<()> {
        self.poll_rx_with_timeout(None)
    }

    /// Like [`poll_rx`] but caps the `poll(2)` wait to at most
    /// `max_timeout_ms` milliseconds.  Pass `None` to use the timer-derived
    /// deadline only (may block indefinitely when no timers are pending).
    pub fn poll_rx_with_timeout(
        &mut self,
        max_timeout_ms: Option<u64>,
    ) -> Result<()> {
        let (uplinks, timers) = (&mut self.uplinks, &mut self.timers);

        // First update: fire already-expired timers, get next deadline.
        let timer_ms = timers.update();

        // Fold TCP socket deadlines into the timeout so we wake up in time
        // to fire RTO / TLP / keep-alive / persist even when no RX arrives.
        let tcp_now = now_ms();
        let tcp_ms: Option<u64> = uplinks
            .iter()
            .flat_map(|u| u.standalone_tcp())
            .filter_map(|s| s.next_deadline_ms(tcp_now))
            .min();

        let effective_ms = match (timer_ms, tcp_ms) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b)             => a.or(b),
        };

        let timeout_ms: libc::c_int = match (effective_ms, max_timeout_ms) {
            (Some(t), Some(m)) => t.min(m).min(libc::c_int::MAX as u64) as libc::c_int,
            (Some(t), None)    => t.min(libc::c_int::MAX as u64) as libc::c_int,
            (None,    Some(m)) => m.min(libc::c_int::MAX as u64) as libc::c_int,
            (None,    None)    => -1,
        };

        if !uplinks.is_empty() {
            let mut pollfds: Vec<libc::pollfd> = uplinks
                .iter()
                .map(|u| libc::pollfd {
                    fd: u.sock.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();

            let rc = unsafe {
                libc::poll(
                    pollfds.as_mut_ptr(),
                    pollfds.len() as libc::nfds_t,
                    timeout_ms,
                )
            };
            if rc < 0 {
                return Err(Error::last_os());
            }

            if rc > 0 {
                for (uplink, pfd) in uplinks.iter_mut().zip(pollfds.iter()) {
                    if pfd.revents & libc::POLLIN != 0 {
                        drain(uplink)?;
                    }
                }
            }

            // Drive TCP polling unconditionally — even on timeout — so that
            // flush_send_buf() is retried when no incoming frames are expected
            // (e.g. server waiting for the client to read data).
            for uplink in uplinks.iter_mut() {
                for s in uplink.standalone_tcp_mut() {
                    let _ = s.poll();
                }
            }
        }

        // Second update: fire any timers that expired during the wait.
        timers.update();

        Ok(())
    }
}

// ── Internal drain helper ─────────────────────────────────────────────────────

/// Drain all available frames from `uplink` and dispatch each to its
/// matching [`Interface`] receive handler.
fn drain<L: EtherLink>(uplink: &mut Uplink<L>) -> Result<()> {
    // Allocate once; 65536-byte frame buffer is too large for a per-iteration
    // stack array, and GRO frames fill most of it so zeroing would dominate.
    let mut frame_buf = alloc::vec![0u8; FRAME_SIZE];
    loop {
        let frame_len = {
            let raw = match uplink.sock.rx_recv() {
                Some(r) => r,
                None => {
                    return Ok(());
                }
            };
            let len = raw.len().min(frame_buf.len());
            frame_buf[..len].copy_from_slice(&raw[..len]);
            len
        };
        uplink.sock.rx_release();

        if frame_len < 6 {
            continue;
        }
        let raw = &frame_buf[..frame_len];

        let dst_mac = MacAddr::from(<[u8; 6]>::try_from(&raw[0..6]).unwrap());

        // Deliver to eth tap callbacks for frames addressed to this uplink's
        // interface MAC(s) or Ethernet broadcast.  Frames for other MACs
        // (promiscuous traffic) are not delivered to the tap.
        let tap_match = dst_mac == MacAddr::BROADCAST
            || uplink.interfaces.iter().any(|i| i.mac() == dst_mac);
        if tap_match {
            for entry in &uplink.eth_callbacks {
                (entry.callback)(raw);
            }
        }

        let (interfaces, udp_sockets, tcp_sockets, standalone_tcp) = (
            &mut uplink.interfaces,
            &mut uplink.udp_sockets,
            &mut uplink.tcp_sockets,
            &mut uplink.standalone_tcp,
        );

        if dst_mac == MacAddr::BROADCAST {
            for iface in interfaces.iter_mut() {
                iface.receive(raw, udp_sockets, tcp_sockets, standalone_tcp)?;
            }
        } else {
            for iface in interfaces.iter_mut() {
                if iface.mac() == dst_mac {
                    iface.receive(raw, udp_sockets, tcp_sockets, standalone_tcp)?;
                    break;
                }
            }
        }
    }
}
