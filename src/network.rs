/// Top-level network runtime.
///
/// A [`Network`] owns a set of [`Uplink`]s — one per physical interface
/// (ifindex) — and a flat [`Vec`] of [`Interface`]s.  Each [`Uplink`] records
/// which interface indices it drives via `iface_indices`.
///
/// [`Network::poll_rx`] is the single entry point for inbound traffic: it
/// updates the timer system, blocks in `ppoll(2)` for the appropriate
/// duration, drains all ready rings, and updates the timer system again.
use core::net::Ipv4Addr;
use crate::{
    arp_cache,
    eth::MacAddr,
    interface::{Interface, InterfaceConfig},
    ip::Ipv4Cidr,
    af_packet::{AfPacketSocket, EtherLink},
    tcp::TcpConfig,
    timers::{Clock, Timers},
    Error, Result,
};
use alloc::{rc::Rc, vec::Vec};

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

    // ── Checksum validation ─────────────────────────────────────────────────

    /// Validate the IPv4 header checksum on received frames.  Default: false.
    ///
    /// When false, the checksum is not verified — safe when the NIC or kernel
    /// has already checked it (the common AF_PACKET case).  Enable for
    /// software-only paths (e.g. VirtualLink in tests).
    pub checksum_validate_ip: bool,

    /// Validate TCP checksums on received segments.  Default: false.
    pub checksum_validate_tcp: bool,

    /// Validate UDP checksums on received datagrams.  Default: false.
    pub checksum_validate_udp: bool,
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
            checksum_validate_ip:          false,
            checksum_validate_tcp:         false,
            checksum_validate_udp:         false,
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
    /// Index into `Network::interfaces` — the egress interface.
    pub intf_idx:   usize,
    /// Source address assigned to the egress interface.
    pub src_ip:     Ipv4Addr,
    /// IP address to resolve via ARP (gateway IP, or `dst_ip` for on-link routes).
    pub nexthop_ip: Ipv4Addr,
}

// ── AnyLink ───────────────────────────────────────────────────────────────────

/// Type-erased Ethernet link.
///
/// Currently wraps only real AF_PACKET sockets.  Virtual/bridge-based
/// interfaces are created without an uplink and receive frames via
/// [`Interface::rx_queue`](crate::interface::Interface::rx_queue) instead.
pub(crate) enum AnyLink {
    AfPacket(AfPacketSocket),
}

impl AnyLink {
    pub(crate) fn kernel_ifindex(&self) -> i32 {
        match self {
            AnyLink::AfPacket(s) => s.kernel_ifindex(),
        }
    }
}

impl EtherLink for AnyLink {
    fn rx_recv(&mut self) -> Option<&[u8]> {
        match self {
            AnyLink::AfPacket(s) => s.rx_recv(),
        }
    }

    fn rx_release(&mut self) {
        match self {
            AnyLink::AfPacket(s) => s.rx_release(),
        }
    }

    fn tx_send(&mut self, frame: &[u8]) -> Result<()> {
        match self {
            AnyLink::AfPacket(s) => s.tx_send(frame),
        }
    }

    fn open_tx(&self) -> Result<crate::TxFn> {
        match self {
            AnyLink::AfPacket(s) => s.open_tx(),
        }
    }

    fn fd(&self) -> libc::c_int {
        match self {
            AnyLink::AfPacket(s) => s.fd(),
        }
    }

    fn attach_mac(&mut self, mac: &MacAddr) -> Result<()> {
        match self {
            AnyLink::AfPacket(s) => s.attach_mac(mac),
        }
    }

    fn detach_mac(&mut self, mac: &MacAddr) -> Result<()> {
        match self {
            AnyLink::AfPacket(s) => s.detach_mac(mac),
        }
    }
}

// ── Uplink ────────────────────────────────────────────────────────────────────

/// One physical uplink: a concrete [`AnyLink`] and the indices of the
/// [`Interface`]s (stored in [`Network::interfaces`]) multiplexed over it.
///
/// # Layer boundary
///
/// `Uplink` is the L1/L2 physical boundary.  It delivers raw Ethernet frames
/// to [`Interface`]s but does **not** parse frame content itself — no EtherType
/// inspection, no header stripping.  All L2/L3 parsing is delegated to
/// [`Interface::receive`], which is the authoritative L2/L3 entry point.
pub struct Uplink {
    pub(crate) sock:         AnyLink,
    pub(crate) iface_indices: Vec<usize>,
}

impl Uplink {
    /// Return the OS file descriptor for this uplink (for use with `poll(2)`).
    pub(crate) fn fd(&self) -> libc::c_int {
        self.sock.fd()
    }

    /// Transmit a raw Ethernet frame via this uplink's TX ring.
    pub(crate) fn tx_send(&mut self, frame: &[u8]) -> Result<()> {
        self.sock.tx_send(frame)
    }

    /// Return the next received Ethernet frame, or None if the ring is empty.
    /// Caller must process the frame before calling again (single-frame contract).
    pub(crate) fn recv_next(&mut self) -> Option<Vec<u8>> {
        let frame = self.sock.rx_recv()?;
        let data = frame.to_vec();
        self.sock.rx_release();
        Some(data)
    }

}

// ── InterfaceBuilder ─────────────────────────────────────────────────────────

/// Fluent builder returned by [`Network::add_interface`].
pub struct InterfaceBuilder<'a> {
    network: &'a mut Network,
    mac:     MacAddr,
}

impl<'a> InterfaceBuilder<'a> {
    /// Attach to a live AF_PACKET socket on the named kernel interface.
    ///
    /// Resolves the kernel ifindex for `ifname`; if an existing [`Uplink`]
    /// already owns that ifindex the new interface shares its socket (enabling
    /// multiple MACs on one AF_PACKET fd).  Otherwise a new socket is opened
    /// and a new `Uplink` is created.
    ///
    /// Returns the interface index (`iface_idx`).
    pub fn bind_afpacket(self, ifname: &[u8]) -> Result<usize> {
        let kernel_ifindex = AfPacketSocket::lookup_kernel_ifindex(ifname)?;

        // Find an existing uplink for this ifindex, or open a new socket.
        let uplink_idx = if let Some(idx) = self.network.uplinks
            .iter()
            .position(|u| u.sock.kernel_ifindex() == kernel_ifindex)
        {
            idx
        } else {
            let sock = AfPacketSocket::open(kernel_ifindex)?;
            self.network.add_uplink_raw(AnyLink::AfPacket(sock))
        };

        let iface = Interface::with_config(
            ifname,
            self.mac,
            Some(kernel_ifindex),
            self.network.interface_config(),
        );
        self.network.attach_to_uplink(uplink_idx, iface)
    }

    /// Create an unbound interface (no AF_PACKET socket, no uplink).
    ///
    /// The interface receives frames only via its
    /// [`rx_queue`](Interface::rx_queue) — suitable for bridge-based test
    /// setups and simulation.  Returns the interface index (`iface_idx`).
    pub fn finish(self) -> usize {
        let iface = Interface::with_config(
            b"",
            self.mac,
            None,
            self.network.interface_config(),
        );
        let iface_idx = self.network.interfaces.len();
        let timers = &mut self.network.timers;
        arp_cache::schedule_expiry(iface.arp_queue().clone(), timers);
        iface.schedule_frag_purge(timers);
        self.network.interfaces.push(iface);
        iface_idx
    }
}

// ── Network ───────────────────────────────────────────────────────────────────

/// Top-level network runtime — owns all uplinks, interfaces, and drives
/// inbound traffic.
///
/// `Network` is concrete (non-generic).  Physical links are abstracted via
/// [`AnyLink`] inside each [`Uplink`].
pub struct Network {
    pub(crate) uplinks:    Vec<Uplink>,
    pub(crate) interfaces: Vec<Interface>,
    config:                NetworkConfig,
    timers:                Timers,
    routes:                Vec<Route>,
    clock:                 Clock,
    /// Closures registered by bridge ports.  Each closure delivers ready
    /// delayed frames and returns the next pending deadline (for poll timeout).
    bridge_delivers: Vec<Rc<dyn Fn() -> Option<u64>>>,
}

impl Default for Network {
    fn default() -> Self { Self::new() }
}

impl Network {
    /// Create a network runtime with default configuration and the Linux clock.
    pub fn new() -> Self {
        Self::with_config(NetworkConfig::default(), Default::default())
    }

    /// Create a network runtime with the given configuration and clock.
    pub fn with_config(config: NetworkConfig, clock: Clock) -> Self {
        Network {
            uplinks:         Vec::new(),
            interfaces:      Vec::new(),
            config,
            timers:          Timers::new(clock.clone()),
            routes:          Vec::new(),
            clock,
            bridge_delivers: Vec::new(),
        }
    }

    /// Return a clone of the internal [`Clock`] handle.
    ///
    /// Use this to wire the clock into a `Bridge` or `WireHarness` so that
    /// frame delivery timestamps are consistent with this network's time.
    ///
    /// In production builds, `Clock` is a zero-sized type; cloning it is
    /// free and calling `monotonic_ms()` reads the system clock directly.
    /// In test builds (`feature = "test-internals"`), the clone shares the
    /// same simulation state so that advancing one advances all holders.
    pub fn clock_ref(&self) -> Clock {
        self.clock.clone()
    }

    /// Register a bridge-port delivery closure.
    ///
    /// Called by [`PortBuilder::finish`](crate::bridge::PortBuilder::finish)
    /// when a bridge port is attached to this network.  The closure is called
    /// at the start of every [`poll_rx_with_timeout`](Self::poll_rx_with_timeout)
    /// to drain delayed frames whose deadline has arrived, and returns the
    /// earliest remaining deadline so the poll timeout can be set accordingly.
    pub fn add_bridge_deliver(&mut self, f: Rc<dyn Fn() -> Option<u64>>) {
        self.bridge_delivers.push(f);
    }

    /// Zero the clock (set apparent time to 0) and return `&mut self` for chaining.
    ///
    /// After this call `clock_monotonic_ms()` returns 0.  Subsequent
    /// `clock_advance_*` calls count from 0.
    #[cfg(feature = "test-internals")]
    pub fn clock_zero(&mut self) -> &mut Self {
        // Replace the shared clock with a freshly zeroed one.  Because
        // clock_ref() callers hold Rc clones of the *old* clock, we advance
        // the existing clock rather than swapping it out.
        let current_ns = self.clock.monotonic_ns() as i64;
        self.clock.advance_ns(-current_ns);
        self
    }

    /// Pause the clock and return `&mut self` for chaining.
    #[cfg(feature = "test-internals")]
    pub fn clock_pause(&mut self) -> &mut Self {
        self.clock.pause();
        self
    }

    /// Resume the clock and return `&mut self` for chaining.
    #[cfg(feature = "test-internals")]
    pub fn clock_resume(&mut self) -> &mut Self {
        self.clock.resume();
        self
    }

    /// Advance the clock by `ms` milliseconds and return `&mut self`.
    #[cfg(feature = "test-internals")]
    pub fn clock_advance_ms(&mut self, ms: i64) -> &mut Self {
        self.clock.advance_ms(ms);
        self
    }

    /// Advance the clock by `us` microseconds and return `&mut self`.
    #[cfg(feature = "test-internals")]
    pub fn clock_advance_us(&mut self, us: i64) -> &mut Self {
        self.clock.advance_us(us);
        self
    }

    /// Return the current monotonic time as seen by this network's clock.
    #[cfg(feature = "test-internals")]
    pub fn clock_monotonic_ms(&self) -> u64 {
        self.clock.monotonic_ms()
    }

    /// Begin adding a new interface with the given MAC address.
    ///
    /// Returns an [`InterfaceBuilder`] — call `.bind_afpacket(ifname)` to
    /// attach to a live AF_PACKET socket or `.finish()` to create an unbound
    /// interface (useful for bridge-based test setups).
    pub fn add_interface(&mut self, mac: MacAddr) -> InterfaceBuilder<'_> {
        InterfaceBuilder { network: self, mac }
    }

    /// Return a mutable reference to the interface at `idx`.
    ///
    /// # Panics
    /// Panics if `idx` is out of bounds.
    pub fn iface_mut(&mut self, idx: usize) -> &mut Interface {
        &mut self.interfaces[idx]
    }

    /// Bundle the network-wide configuration and clock into an
    /// [`InterfaceConfig`] for constructing a new [`Interface`].
    pub(crate) fn interface_config(&self) -> InterfaceConfig {
        InterfaceConfig {
            arp_cache_max_age_ms:    self.config.arp_cache_max_age_ms,
            arp_cache_max_entries:   self.config.arp_cache_max_entries,
            arp_queue_max_pending:   self.config.arp_queue_max_pending,
            ip_frag_timeout_ms:      self.config.ip_frag_timeout_ms,
            ip_frag_mem_limit:       self.config.ip_frag_mem_limit,
            ip_frag_per_src_max:     self.config.ip_frag_per_src_max,
            icmp_rate_limit_per_sec: self.config.icmp_rate_limit_per_sec,
            checksum_validate_ip:    self.config.checksum_validate_ip,
            checksum_validate_tcp:   self.config.checksum_validate_tcp,
            checksum_validate_udp:   self.config.checksum_validate_udp,
            clock:                   self.clock.clone(),
        }
    }

    /// Register an [`AnyLink`] as a new uplink.
    ///
    /// Returns the uplink index.
    fn add_uplink_raw(&mut self, sock: AnyLink) -> usize {
        self.uplinks.push(Uplink {
            sock,
            iface_indices: Vec::new(),
        });
        self.uplinks.len() - 1
    }

    /// Wire an [`Interface`] to an existing uplink at `uplink_idx`.
    ///
    /// Registers the MAC with the BPF filter, sets the TX closure, starts
    /// ARP and fragment-purge timers.  Returns the `iface_idx`.
    fn attach_to_uplink(&mut self, uplink_idx: usize, iface: Interface) -> Result<usize> {
        let iface_idx = self.interfaces.len();

        let timers = &mut self.timers;
        let uplink = &mut self.uplinks[uplink_idx];

        uplink.sock.attach_mac(&iface.mac())?;
        let mut iface = iface;
        iface.set_tx(uplink.sock.open_tx()?);
        arp_cache::schedule_expiry(iface.arp_queue().clone(), timers);
        iface.schedule_frag_purge(timers);
        uplink.iface_indices.push(iface_idx);

        self.interfaces.push(iface);
        Ok(iface_idx)
    }

    /// Detach and remove the interface with the given MAC from `uplink_idx`.
    ///
    /// Marks the interface's ARP queue as dead, stopping all self-rescheduling
    /// timers, and removes the MAC from the BPF filter.
    /// Returns the removed [`Interface`] if found, `None` otherwise.
    pub fn detach_interface(&mut self, uplink_idx: usize, mac: &MacAddr) -> Result<Option<Interface>> {
        let uplink = match self.uplinks.get_mut(uplink_idx) {
            Some(u) => u,
            None    => return Ok(None),
        };

        // Find the interface index inside this uplink.
        let pos = uplink.iface_indices.iter().position(|&idx| {
            self.interfaces.get(idx).is_some_and(|i| &i.mac() == mac)
        });
        let Some(pos) = pos else { return Ok(None) };
        let iface_idx = uplink.iface_indices.remove(pos);

        // Mark ARP dead and detach BPF.
        self.interfaces[iface_idx].arp_queue().mark_dead();
        uplink.sock.detach_mac(mac)?;

        // Swap-remove from interfaces vec. Update any iface_indices that
        // pointed at the last element (which moves to iface_idx after swap).
        let last_idx = self.interfaces.len() - 1;
        let removed = if iface_idx == last_idx {
            self.interfaces.remove(iface_idx)
        } else {
            // Find uplink that owns last_idx and update its reference.
            for u in &mut self.uplinks {
                for idx_ref in &mut u.iface_indices {
                    if *idx_ref == last_idx {
                        *idx_ref = iface_idx;
                    }
                }
            }
            self.interfaces.swap_remove(iface_idx)
        };

        Ok(Some(removed))
    }

    /// Return a reference to the interface at `idx`, or `None` if out of bounds.
    pub fn iface(&self, idx: usize) -> Option<&Interface> {
        self.interfaces.get(idx)
    }

    pub(crate) fn uplinks_mut(&mut self) -> &mut [Uplink] {
        &mut self.uplinks
    }

    pub(crate) fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    pub(crate) fn interfaces_mut(&mut self) -> &mut [Interface] {
        &mut self.interfaces
    }

    /// Return the uplink index that owns interface `iface_idx`, or `None`.
    pub(crate) fn uplink_for_iface(&self, iface_idx: usize) -> Option<usize> {
        self.uplinks.iter().position(|u| u.iface_indices.contains(&iface_idx))
    }

    /// Return a mutable reference to the uplink at `idx`.
    ///
    /// # Panics
    /// Panics if `idx` is out of bounds.
    pub fn uplink_mut(&mut self, idx: usize) -> &mut Uplink {
        &mut self.uplinks[idx]
    }

    /// Replace the MAC on the first attached interface of uplink `uplink_idx`,
    /// updating the BPF filter accordingly.
    /// Change the MAC address on interface `iface_idx`, updating the BPF
    /// filter on the backing uplink (if any).
    pub(crate) fn set_iface_mac(&mut self, iface_idx: usize, new_mac: MacAddr) -> Result<()> {
        let iface = self.interfaces.get_mut(iface_idx).ok_or(Error::InvalidInput)?;
        let old = iface.mac();
        iface.set_mac(new_mac);

        // Update BPF filter on the uplink that carries this interface, if any.
        if let Some(uplink_idx) = self.uplink_for_iface(iface_idx) {
            self.uplinks[uplink_idx].sock.detach_mac(&old)?;
            self.uplinks[uplink_idx].sock.attach_mac(&new_mac)?;
        }
        Ok(())
    }

    /// Find the interface index and interface assigned `src_ip`, and return the
    /// network-derived [`TcpConfig`] alongside it.
    ///
    /// Returns `None` if no attached interface has that IP.
    pub(crate) fn find_iface_for_src_ip(
        &self,
        src_ip: Ipv4Addr,
    ) -> Option<(usize, &Interface, TcpConfig)> {
        let cfg = self.config.tcp_config();
        for (idx, iface) in self.interfaces.iter().enumerate() {
            if iface.ip().is_some_and(|c| c.addr() == src_ip) {
                return Some((idx, iface, cfg));
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
        for (idx, iface) in self.interfaces.iter().enumerate() {
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
        None
    }

    /// Return the network-level [`TcpConfig`].
    pub(crate) fn tcp_config(&self) -> TcpConfig {
        self.config.tcp_config()
    }

    /// Dispatch inbound frames and drive the timer system.
    ///
    /// Equivalent to `poll_rx_with_timeout(None)`.  Uses `ppoll(2)` for
    /// nanosecond-resolution wakeups.
    pub fn poll_rx(&mut self) -> Result<()> {
        self.poll_rx_with_timeout(None)
    }

    /// Like [`poll_rx`] but caps the `ppoll(2)` wait to at most
    /// `max_timeout_ms` milliseconds.  Pass `None` to use the timer-derived
    /// deadline only (may block indefinitely when no timers are pending).
    pub fn poll_rx_with_timeout(
        &mut self,
        max_timeout_ms: Option<u64>,
    ) -> Result<()> {
        // Drive bridge deliver closures first: drain any delayed frames whose
        // deadline has arrived, and collect the next pending deadline (ns).
        let bridge_ns: Option<u64> = {
            let now_ns = self.timers.clock().monotonic_ns();
            self.bridge_delivers
                .iter()
                .filter_map(|f| f())
                .min()
                .map(|deadline_ns| deadline_ns.saturating_sub(now_ns))
        };

        // First update: fire already-expired timers, get next deadline (ns).
        let timer_ns = self.timers.update();

        // Fold TCP socket deadlines (ns) into the timeout so we wake up in
        // time to fire RTO / TLP / keep-alive / persist / pacing even when no
        // RX arrives.
        let tcp_now = self.timers.clock().monotonic_ns();
        let tcp_ns: Option<u64> = self.interfaces
            .iter()
            .flat_map(|i| i.tcp_sockets.iter())
            .filter_map(|s| s.next_deadline_ns(tcp_now))
            .min();

        // Combine all ns deadlines; apply optional ms ceiling.
        let max_ns = max_timeout_ms.map(|ms| ms * 1_000_000);
        let effective_ns: Option<u64> =
            [timer_ns, tcp_ns, bridge_ns, max_ns].into_iter().flatten().min();

        if !self.uplinks.is_empty() {
            let mut pollfds: Vec<libc::pollfd> = self.uplinks
                .iter()
                .map(|u| libc::pollfd {
                    fd: u.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();

            let rc = unsafe {
                // ppoll(2): nanosecond-resolution timeout; null timespec = block
                // indefinitely; null sigmask = no mask change.
                let ts = effective_ns.map(|ns| libc::timespec {
                    tv_sec:  (ns / 1_000_000_000) as i64,
                    tv_nsec: (ns % 1_000_000_000) as libc::c_long,
                });
                libc::ppoll(
                    pollfds.as_mut_ptr(),
                    pollfds.len() as libc::nfds_t,
                    ts.as_ref().map_or(core::ptr::null(), |p| p as *const _),
                    core::ptr::null(),
                )
            };
            if rc < 0 {
                return Err(Error::last_os());
            }

            if rc > 0 {
                for (u_idx, pfd) in pollfds.iter().enumerate() {
                    if pfd.revents & libc::POLLIN != 0 {
                        drain(u_idx, &mut self.uplinks, &mut self.interfaces)?;
                    }
                }
            }
        } else if !self.interfaces.is_empty() {
            // No AF_PACKET uplinks — bridge-based or virtual interfaces.
            // When bridge deliver closures are registered, timing is driven by
            // virtual clocks advanced explicitly by the caller; real-time sleep
            // would only waste wall-clock time and is skipped.
            if self.bridge_delivers.is_empty() {
                if let Some(ns) = effective_ns {
                    if ns > 0 {
                        let ts = libc::timespec {
                            tv_sec:  (ns / 1_000_000_000) as i64,
                            tv_nsec: (ns % 1_000_000_000) as libc::c_long,
                        };
                        unsafe { libc::nanosleep(&ts, core::ptr::null_mut()) };
                    }
                }
            }
        }

        // Drive all interfaces — drains their rx_queue (bridge inject)
        // and fires TCP timer callbacks (RTO, TLP, keep-alive, TimeWait).
        for iface in &mut self.interfaces {
            iface.poll();
        }

        // Second update: fire any timers that expired during the wait.
        self.timers.update();

        Ok(())
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Drain all available frames from `uplinks[u_idx]` and dispatch each to the
/// matching [`Interface`] receive handler.
///
/// # Layer boundary
///
/// This function is the seam between L1/L2 and L3:
///
/// - **[`Uplink`]** is the physical layer.  It delivers raw Ethernet frames
///   as opaque byte slices without interpreting content.
/// - **`drain`** performs the single L2 demux needed to route the frame to the
///   correct [`Interface`]: it reads only the 6-byte Ethernet destination MAC
///   from the front of the frame to match against registered interface MACs.
/// - **[`Interface::receive`]** owns all L2/L3 parsing.
fn drain(
    u_idx:      usize,
    uplinks:    &mut [Uplink],
    interfaces: &mut [Interface],
) -> Result<()> {
    loop {
        let raw = match uplinks[u_idx].recv_next() {
            Some(r) => r,
            None    => return Ok(()),
        };

        if raw.len() < 6 {
            continue;
        }

        let dst_mac = MacAddr::from(<[u8; 6]>::try_from(&raw[0..6]).unwrap());

        if dst_mac == MacAddr::BROADCAST {
            for &iface_idx in &uplinks[u_idx].iface_indices {
                interfaces[iface_idx].receive(&raw)?;
            }
        } else {
            for &iface_idx in &uplinks[u_idx].iface_indices {
                if interfaces[iface_idx].mac() == dst_mac {
                    interfaces[iface_idx].receive(&raw)?;
                    break;
                }
            }
        }
    }
}
