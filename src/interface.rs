/// Virtual NIC descriptor — a Layer-3 identity on a physical uplink.
///
/// Each `Interface` has a MAC address and an optional IPv4 CIDR.  It does not
/// own an AF_PACKET socket; instead it is driven by [`Network::poll_rx`],
/// which performs Layer-2 dispatch and calls [`Interface::receive`] for each
/// frame whose Ethernet destination matches this interface's MAC.
///
/// The interface's TX path is an injectable `Rc<dyn Fn>` set by
/// [`Uplink::attach`](crate::Uplink::attach).  All sockets created from this
/// interface clone that `Rc` so they share the same TX path.  In tests the
/// closure is replaced with a `VirtualLink` callback before attaching.
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::RefCell;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::sync::atomic::{AtomicU32, Ordering};

/// Rawket-managed, process-local interface identifier.
///
/// Allocated by a monotonically increasing `AtomicU32` counter; guaranteed
/// unique within the process lifetime across all interface types (real and
/// dummy).  This is distinct from the Linux kernel's interface index
/// (`kernel_ifindex: i32`), which is only present on kernel-backed interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IfIndex(u32);

static NEXT_IFINDEX: AtomicU32 = AtomicU32::new(1);

impl IfIndex {
    fn alloc() -> Self { IfIndex(NEXT_IFINDEX.fetch_add(1, Ordering::Relaxed)) }
    pub fn as_u32(self) -> u32 { self.0 }
}
use crate::{
    arp::{ArpHdr, ArpOp, HDR_LEN as ARP_HDR_LEN},
    arp_cache::ArpQueue,
    eth::{EthHdr, EtherType, MacAddr, HDR_LEN as ETH_HDR_LEN},
    icmp::{IcmpMessage, HDR_LEN as ICMP_HDR_LEN},
    ip::{
        IpProto, Ipv4Cidr, Ipv4Hdr, FLAG_MF,
        MIN_HDR_LEN as IP_HDR_LEN,
    },
    af_packet::{AfPacketSocket, FRAME_SIZE},
    tcp::{self, SeqNum, TcpFlags, TcpHdr, HDR_LEN as TCP_HDR_LEN, TcpSocket},
    timers::{Clock, Deadline, Timers},

    udp::{self, UdpSocket},
    Result,
};

/// Default ARP cache entry lifetime used when an `Interface` is first created.
/// Overridden by [`NetworkConfig::arp_cache_max_age_ms`] when the interface is
/// attached to an [`Uplink`](crate::Uplink).
const DEFAULT_ARP_MAX_AGE_MS: u64 = 20_000;

/// Default fragment-reassembly timeout (ms). Overridden by
/// [`NetworkConfig::ip_frag_timeout_ms`].
const DEFAULT_FRAG_TIMEOUT_MS: u64 = 30_000;

/// Default fragment-reassembly memory limit (bytes). Overridden by
/// [`NetworkConfig::ip_frag_mem_limit`].
const DEFAULT_FRAG_MEM_LIMIT: usize = 65_536;

// ── Fragment reassembly ───────────────────────────────────────────────────────

/// Key that identifies a set of fragments belonging to the same original datagram.
///
/// RFC 791 requires (src, dst, protocol, identification) for uniqueness.
#[derive(PartialEq)]
struct ReassemblyKey {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    id:     u16,
    proto:  IpProto,
}

/// One received fragment: its byte offset into the reassembled payload and the
/// payload bytes it carries.
struct Fragment {
    /// Byte offset (not 8-byte units) into the reassembled IP payload.
    offset: usize,
    data:   Vec<u8>,
}

/// In-flight reassembly state for one original datagram.
struct ReassemblyEntry {
    key:         ReassemblyKey,
    /// Ethernet header copied from the first fragment received (used when
    /// building the reassembled frame).
    eth_hdr:     EthHdr,
    /// IP header from the fragment with offset=0 (updated on arrival); used as
    /// the template when emitting the reassembled packet.
    ip_hdr:      Ipv4Hdr,
    /// Received fragments, kept sorted by offset.
    fragments:   Vec<Fragment>,
    /// Running total of fragment payload bytes stored in this entry.
    total_bytes: usize,
    /// Set when a fragment with MF=0 arrives: the total reassembled payload
    /// length in bytes.
    total_len:   Option<usize>,
    /// Deadline after which this entry is considered expired and will be
    /// removed by the next [`ReassemblyTable::purge`] sweep.
    deadline:    Deadline,
}

impl ReassemblyEntry {
    /// Return `true` when enough fragments have arrived to reconstruct the
    /// original payload without gaps.
    fn is_complete(&self) -> bool {
        let Some(total) = self.total_len else { return false };
        let mut covered = 0usize;
        for frag in &self.fragments {
            if frag.offset > covered {
                return false; // gap before this fragment
            }
            covered = covered.max(frag.offset + frag.data.len());
        }
        covered >= total
    }
}

/// Per-interface fragment reassembly table.
struct ReassemblyTable {
    entries:     Vec<ReassemblyEntry>,
    /// Running total of fragment bytes across all live entries.
    total_bytes: usize,
    /// Bytes-in-use threshold above which new (unseen-key) fragments are
    /// silently dropped.  Fragments for already-tracked keys are always accepted.
    mem_limit:   usize,
    /// How long to wait for remaining fragments before discarding a partial
    /// reassembly, in milliseconds.
    timeout_ms:  u64,
    /// Maximum concurrent reassembly entries per source IP.  When a new
    /// fragment stream from a source already has this many open entries, the
    /// new fragment is dropped.  Default: 4.
    per_src_max: usize,
    /// Time source; used by `insert` (deadline arming) and `purge`.
    clock:       Clock,
}

// ── ICMP rate limiter ─────────────────────────────────────────────────────────

/// Lazy token-bucket rate limiter for outbound ICMP Unreachable messages.
///
/// Tokens are replenished lazily at call time based on elapsed wall-clock time.
/// A `rate_per_sec` of 0 disables rate limiting (unlimited).
struct IcmpRateLimit {
    tokens:       u32,
    last_refill:  u64,
    rate_per_sec: u32,
    burst:        u32,
}

impl IcmpRateLimit {
    fn new(rate_per_sec: u32) -> Self {
        IcmpRateLimit {
            tokens:       rate_per_sec, // start full
            last_refill:  0,
            rate_per_sec,
            burst:        rate_per_sec,
        }
    }

    /// Returns `true` if an ICMP Unreachable may be sent, consuming one token.
    /// `now` is `clock.monotonic_ms()` from the owning `Interface`.
    fn allow(&mut self, now: u64) -> bool {
        if self.rate_per_sec == 0 {
            return true; // unlimited
        }
        let elapsed_ms = now.saturating_sub(self.last_refill);
        let add = ((elapsed_ms.saturating_mul(self.rate_per_sec as u64)) / 1000) as u32;
        if add > 0 {
            self.tokens = self.tokens.saturating_add(add).min(self.burst);
            self.last_refill = now;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

impl ReassemblyTable {
    fn new(mem_limit: usize, timeout_ms: u64, clock: Clock) -> Self {
        ReassemblyTable {
            entries:     Vec::new(),
            total_bytes: 0,
            mem_limit,
            timeout_ms,
            per_src_max: 4,
            clock,
        }
    }

    /// Remove entries whose deadline has expired, reclaiming their memory.
    fn purge(&mut self) {
        let before = self.entries.len();
        let now = self.clock.monotonic_ms();
        self.entries.retain(|e| !e.deadline.is_expired(now));
        if self.entries.len() != before {
            self.total_bytes = self.entries.iter().map(|e| e.total_bytes).sum();
        }
    }

    /// Insert a fragment.  Returns a complete reassembled Ethernet frame (as a
    /// heap-allocated byte vector) if this fragment completes the datagram, or
    /// `None` if reassembly is still in progress (or the fragment was dropped).
    fn insert(
        &mut self,
        eth:     EthHdr,
        ip:      Ipv4Hdr,
        ip_buf:  &[u8],
    ) -> Option<Vec<u8>> {
        self.purge(); // reclaim timed-out entries on every insert
        let key = ReassemblyKey {
            src_ip: ip.src,
            dst_ip: ip.dst,
            id:     ip.id,
            proto:  ip.proto,
        };
        let frag_offset = ip.frag_offset_bytes();
        let payload     = ip.payload(ip_buf);
        let frag_bytes  = payload.len();
        let more_frags  = (ip.flags_frag & FLAG_MF) != 0;
        let now         = self.clock.monotonic_ms();

        // ── Locate or create a reassembly entry ──────────────────────────────

        let entry_idx = self.entries.iter().position(|e| e.key == key);

        if entry_idx.is_none() {
            // New datagram.  Drop if the memory budget is exhausted.
            if self.total_bytes + frag_bytes > self.mem_limit {
                return None;
            }
            // Drop if this source already has too many open reassembly entries.
            let src_count = self.entries.iter().filter(|e| e.key.src_ip == key.src_ip).count();
            if src_count >= self.per_src_max {
                return None;
            }

            let total_len = if !more_frags {
                let tl = frag_offset + frag_bytes;
                // Max IPv4 payload is 65535 - IP_HDR_LEN; reject oversized.
                if tl > 65535 - IP_HDR_LEN { return None; }
                Some(tl)
            } else {
                None
            };

            let entry = ReassemblyEntry {
                key,
                eth_hdr:     eth,
                ip_hdr:      ip,
                fragments:   vec![Fragment { offset: frag_offset, data: payload.to_vec() }],
                total_bytes: frag_bytes,
                total_len,
                deadline:    Deadline::from_now(self.timeout_ms, now),
            };

            self.total_bytes += frag_bytes;
            self.entries.push(entry);

            let idx = self.entries.len() - 1;
            return self.try_reassemble(idx);
        }

        // ── Add fragment to existing entry ────────────────────────────────────

        let idx        = entry_idx.unwrap();
        let added_bytes = {
            let entry = &mut self.entries[idx];

            // Prefer the offset=0 fragment as the IP header template.
            // RFC 791 guarantees that offset=0 carries the definitive IP
            // header; if it arrives late (after higher-offset fragments) we
            // overwrite the placeholder — this is correct behaviour.
            if frag_offset == 0 {
                entry.ip_hdr  = ip;
                entry.eth_hdr = eth;
            }

            // Record total payload length from the terminal fragment (MF=0).
            if !more_frags {
                let tl = frag_offset + frag_bytes;
                if tl > 65535 - IP_HDR_LEN { return None; }
                entry.total_len = Some(tl);
            }

            // Insert in offset order; detect overlaps and exact duplicates.
            let frag_end = frag_offset + frag_bytes;
            let pos = entry.fragments.partition_point(|f| f.offset < frag_offset);

            // Check overlap with the preceding fragment.
            if pos > 0 {
                let prev = &entry.fragments[pos - 1];
                if prev.offset + prev.data.len() > frag_offset {
                    return None; // overlapping fragment — drop entire datagram
                }
            }
            // Check overlap with the next fragment.
            if pos < entry.fragments.len()
                && frag_end > entry.fragments[pos].offset
            {
                return None; // overlapping fragment — drop entire datagram
            }

            if pos < entry.fragments.len() && entry.fragments[pos].offset == frag_offset {
                0 // exact duplicate — no change
            } else {
                entry.fragments.insert(pos, Fragment {
                    offset: frag_offset,
                    data:   payload.to_vec(),
                });
                entry.total_bytes += frag_bytes;
                frag_bytes
            }
        };
        self.total_bytes += added_bytes;

        self.try_reassemble(idx)
    }

    /// If entry `idx` is complete, build the reassembled frame, remove the
    /// entry, and return the frame.  Returns `None` while still incomplete.
    fn try_reassemble(&mut self, idx: usize) -> Option<Vec<u8>> {
        if !self.entries[idx].is_complete() {
            return None;
        }

        let frame = self.build_frame(idx);
        let entry = self.entries.remove(idx);
        self.total_bytes -= entry.total_bytes;
        Some(frame)
    }

    /// Build the reassembled Ethernet+IP frame for entry `idx` (must be
    /// complete).
    fn build_frame(&self, idx: usize) -> Vec<u8> {
        let entry        = &self.entries[idx];
        let total_payload = entry.total_len.unwrap_or(0);
        let frame_len    = ETH_HDR_LEN + IP_HDR_LEN + total_payload;

        let mut frame = vec![0u8; frame_len];

        // Ethernet header — from stored template.
        entry.eth_hdr.emit(&mut frame[..ETH_HDR_LEN]).ok();

        // IP header — template with corrected total_len; fragmentation cleared.
        let mut ip_hdr   = entry.ip_hdr;
        ip_hdr.total_len  = (IP_HDR_LEN + total_payload) as u16;
        ip_hdr.flags_frag = 0;
        ip_hdr.emit(&mut frame[ETH_HDR_LEN..]).ok();

        // Payload — paste each fragment at its byte offset.
        let base = ETH_HDR_LEN + IP_HDR_LEN;
        for frag in &entry.fragments {
            let start = base + frag.offset;
            let end   = start + frag.data.len();
            if end <= frame.len() {
                frame[start..end].copy_from_slice(&frag.data);
            }
        }

        frame
    }
}

// ── Interface ─────────────────────────────────────────────────────────────────

pub struct Interface {
    /// NUL-padded, IFNAMSIZ (16) bytes.
    ifname_buf:     [u8; 16],
    mac:            MacAddr,
    ifindex:        IfIndex,       // rawket-owned, always present
    kernel_ifindex: Option<i32>,   // Linux kernel index; None for dummy interfaces
    ip:             Option<Ipv4Cidr>,
    tx_id:      u16,
    /// Shared TX path — set by [`Uplink::attach`](crate::Uplink::attach).
    /// All sockets created from this interface clone this `Rc`.
    /// Defaults to a no-op until `attach` wires it up.
    tx:         crate::TxFn,
    /// ARP cache + outbound frame queue, shared with all sockets on this
    /// interface.  Both the cache and the queue are per-interface: entries
    /// are learned from frames arriving on this L2 interface only, and
    /// queued frames are routed out of this interface's uplink.
    arp:        ArpQueue,
    /// Fragment reassembly table, shared with the periodic purge timer.
    reasm:      Rc<RefCell<ReassemblyTable>>,
    /// Token-bucket rate limiter for outbound ICMP Unreachable messages.
    icmp_rl:    IcmpRateLimit,
    /// Time source — injected by [`Uplink::attach`] via [`set_clock`].
    clock:      Clock,
}

impl Interface {
    /// Resolve `uplink`'s kernel interface index and create an AF_PACKET-backed
    /// interface with the given MAC.
    /// `uplink` must be a NUL-terminated byte slice (e.g. `b"eth0\0"`).
    ///
    /// No AF_PACKET socket is opened here.  Attach this interface to a shared
    /// [`AfPacketSocket`] via [`Uplink::attach`](crate::Uplink::attach).
    pub fn afpacket(uplink: &[u8], mac: MacAddr) -> Result<Self> {
        let kernel_ifindex = AfPacketSocket::kernel_ifindex(uplink)?;
        let mut ifname_buf = [0u8; 16];
        let len = uplink.len().min(16);
        ifname_buf[..len].copy_from_slice(&uplink[..len]);
        let clock = Clock::default();
        Ok(Interface {
            ifname_buf,
            mac,
            ifindex:        IfIndex::alloc(),
            kernel_ifindex: Some(kernel_ifindex),
            ip: None,
            tx_id: 0,
            tx:      Rc::new(|_| Ok(())),
            arp:     ArpQueue::new(DEFAULT_ARP_MAX_AGE_MS, clock.clone()),
            reasm:   Rc::new(RefCell::new(ReassemblyTable::new(
                DEFAULT_FRAG_MEM_LIMIT, DEFAULT_FRAG_TIMEOUT_MS, clock.clone(),
            ))),
            icmp_rl: IcmpRateLimit::new(100),
            clock,
        })
    }

    /// Create a dummy interface that is not backed by a real kernel interface.
    ///
    /// Useful when the uplink is an [`EtherLink`](crate::af_packet::EtherLink)
    /// that does not require kernel packet-socket registration (e.g. an
    /// in-process virtual wire used in tests).
    pub fn dummy(mac: MacAddr) -> Self {
        let clock = Clock::default();
        Interface {
            ifname_buf:     [0u8; 16],
            mac,
            ifindex:        IfIndex::alloc(),
            kernel_ifindex: None,
            ip:             None,
            tx_id:          0,
            tx:             Rc::new(|_| Ok(())),
            arp:            ArpQueue::new(DEFAULT_ARP_MAX_AGE_MS, clock.clone()),
            reasm:          Rc::new(RefCell::new(ReassemblyTable::new(
                DEFAULT_FRAG_MEM_LIMIT, DEFAULT_FRAG_TIMEOUT_MS, clock.clone(),
            ))),
            icmp_rl:        IcmpRateLimit::new(100),
            clock,
        }
    }
}

impl Interface {
    /// Consume and drop the interface descriptor.
    pub fn remove(self) {
        drop(self);
    }

    pub fn mac(&self) -> MacAddr {
        self.mac
    }

    /// NUL-terminated slice into the internal name buffer.
    pub fn ifname(&self) -> &[u8] {
        let nul = self.ifname_buf.iter().position(|&b| b == 0).unwrap_or(15);
        &self.ifname_buf[..=nul]
    }

    pub fn ifindex(&self) -> IfIndex {
        self.ifindex
    }

    pub fn kernel_ifindex(&self) -> Option<i32> {
        self.kernel_ifindex
    }

    /// Assign an IPv4 address and network prefix to this interface.
    ///
    /// Replaces any previously assigned address.
    pub fn assign_ip(&mut self, cidr: Ipv4Cidr) {
        self.ip = Some(cidr);
    }

    /// Return the assigned IPv4 address and prefix, if any.
    pub fn ip(&self) -> Option<Ipv4Cidr> {
        self.ip
    }

    pub(crate) fn set_mac(&mut self, mac: MacAddr) {
        self.mac = mac;
    }

    /// Set the TX closure used by this interface and all sockets cloned from it.
    ///
    /// Called by [`Uplink::attach`](crate::Uplink::attach) in production and
    /// by the test harness to inject a `VirtualLink` TX path.
    pub(crate) fn set_tx(&mut self, tx: crate::TxFn) {
        self.tx = tx;
    }

    /// Clone the shared TX closure for use by a socket.
    pub(crate) fn tx(&self) -> crate::TxFn {
        Rc::clone(&self.tx)
    }

    /// Inject the network-wide shared clock.
    ///
    /// Called by [`Uplink::attach`](crate::Uplink::attach) so that this
    /// interface and all objects derived from it use the same time source.
    /// Must be called before any sockets are created from this interface.
    pub(crate) fn set_clock(&mut self, clock: Clock) {
        self.clock = clock.clone();
        self.arp.set_clock(clock.clone());
        self.reasm.borrow_mut().clock = clock;
    }

    /// Return a reference to the clock driving this interface.
    ///
    /// Socket constructors clone it to propagate the time source.
    pub(crate) fn clock(&self) -> &Clock { &self.clock }

    /// Return a reference to this interface's combined ARP cache + frame queue.
    ///
    /// Sockets clone this at construction time to share the same cache and
    /// queue.  [`Uplink::attach`](crate::Uplink::attach) also uses it to
    /// install the recurring expiry timer.
    pub(crate) fn arp_queue(&self) -> &ArpQueue {
        &self.arp
    }

    /// Look up the MAC address for `ip` in this interface's ARP cache.
    ///
    /// Returns `None` if no non-expired entry exists.
    pub fn arp_lookup(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        self.arp.lookup(ip)
    }

    /// Insert a static ARP entry mapping `ip` to `mac`.
    ///
    /// Useful for pre-seeding the cache on interfaces where ARP exchanges are
    /// undesirable (e.g. dummy interfaces used in tests, or statically
    /// configured point-to-point links).  The entry obeys the normal TTL and
    /// will be refreshed on cache lookup; call this again if you need a
    /// permanent entry that survives expiry.
    pub fn seed_arp(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        self.arp.insert(ip, mac);
    }

    /// Override the fragment-reassembly settings applied by
    /// [`Uplink::attach`](crate::Uplink::attach).
    pub(crate) fn set_frag_config(&mut self, timeout_ms: u64, mem_limit: usize, per_src_max: usize) {
        let mut t        = self.reasm.borrow_mut();
        t.timeout_ms     = timeout_ms;
        t.mem_limit      = mem_limit;
        t.per_src_max    = per_src_max;
    }

    /// Set the ICMP Unreachable rate limit (tokens per second; 0 = unlimited).
    pub(crate) fn set_icmp_rate_limit(&mut self, rate_per_sec: u32) {
        self.icmp_rl = IcmpRateLimit::new(rate_per_sec);
    }

    /// Install a 1-second periodic timer that purges timed-out reassembly
    /// entries even when no new fragments arrive.
    pub(crate) fn schedule_frag_purge(&self, timers: &mut Timers) {
        schedule_frag_purge_inner(Rc::clone(&self.reasm), timers);
    }

    // ── L3 receive handler ───────────────────────────────────────────────────

    /// Process one inbound Ethernet frame at Layer 3.
    ///
    /// Called by the `drain` loop after L2 destination-MAC dispatch.
    /// Response frames (ICMP unreachables, TCP resets, ARP replies) are
    /// sent via the interface's injected TX closure.
    ///
    /// Dispatch rules:
    /// - `ETHERTYPE_ARP` → if `tpa == interface IP`: sender SHA/SPA inserted and pending sends
    ///   flushed (regardless of REQUEST vs REPLY);
    ///   Request → ARP Reply sent; Reply → queued sends flushed.
    /// - Non-IPv4, non-ARP EtherType → silently ignored.
    /// - `ip.dst != interface IP` → silently dropped.
    /// - Fragmented IPv4 → queued for reassembly; dispatched when complete.
    /// - `proto == ICMP` → passed through (no auto-response).
    /// - `proto == UDP` → forwarded to [`udp::dispatch`].
    /// - `proto == TCP` → forwarded to [`tcp::dispatch`].
    /// - Any other proto → ICMP Type 3 Code 2.
    pub fn receive(
        &mut self,
        raw:            &[u8],
        udp_sockets:    &mut [UdpSocket],
        tcp_sockets:    &mut [TcpSocket],
        standalone_tcp: &mut [TcpSocket],
    ) -> Result<()> {
        let cidr = match self.ip {
            Some(c) => c,
            None => return Ok(()),
        };

        let eth = match EthHdr::parse(raw) {
            Ok(e)  => e,
            Err(_) => return Ok(()),
        };

        match eth.ethertype {
            EtherType::ARP => {
                if let Ok(arp) = ArpHdr::parse(eth.payload(raw)) {
                    if arp.tpa == cidr.addr() {
                        // Targeted at us: insert into this interface's cache
                        // and drain all queued frames for the now-known MAC.
                        self.arp.insert(arp.spa, arp.sha);

                        for frame in self.arp.drain_for(arp.spa, arp.sha) {
                            (self.tx)(&frame)?;
                        }

                        if arp.oper == ArpOp::REQUEST {
                            self.send_arp_reply(&arp)?;
                        }
                    }
                    // Frames not targeted at us are ignored.  We intentionally
                    // do not update existing cache entries from unsolicited
                    // (gratuitous) ARP traffic: doing so would let an attacker
                    // on the same L2 segment poison the ARP cache for any IP
                    // by broadcasting crafted gratuitous ARP replies.
                }
            }
            EtherType::IPV4 => {
                let ip_buf = eth.payload(raw);
                let ip = match Ipv4Hdr::parse(ip_buf) {
                    Ok(h)  => h,
                    Err(_) => return Ok(()),
                };

                // Accept frames addressed to our unicast IP, our subnet's
                // directed broadcast, or the limited broadcast 255.255.255.255.
                // Anything else is silently dropped.
                let is_broadcast = ip.dst == cidr.broadcast()
                    || ip.dst == Ipv4Addr::BROADCAST;
                if ip.dst != cidr.addr() && !is_broadcast {
                    return Ok(());
                }

                if ip.is_fragment() {
                    let maybe_frame = self.reasm.borrow_mut().insert(eth, ip, ip_buf);
                    if let Some(frame) = maybe_frame {
                        self.dispatch_ipv4(&frame, udp_sockets, tcp_sockets, standalone_tcp)?;
                    }
                    return Ok(());
                }

                self.dispatch_ipv4(raw, udp_sockets, tcp_sockets, standalone_tcp)?;
            }
            _ => {} // unknown EtherType — silently ignore
        }

        Ok(())
    }

    // ── Private IPv4 L4 dispatch ─────────────────────────────────────────────

    /// Dispatch a complete (non-fragmented, or freshly reassembled) IPv4 frame
    /// to the appropriate L4 handler.
    ///
    /// `raw` must be a valid Ethernet+IPv4 frame.
    fn dispatch_ipv4(
        &mut self,
        raw:            &[u8],
        udp_sockets:    &mut [UdpSocket],
        tcp_sockets:    &mut [TcpSocket],
        standalone_tcp: &mut [TcpSocket],
    ) -> Result<()> {
        let eth    = EthHdr::parse(raw)?;
        let ip_buf = eth.payload(raw);
        let ip     = Ipv4Hdr::parse(ip_buf)?;

        // Drop packets with martian source addresses before any L4 dispatch.
        let own_ip = self.ip.map(|c| c.addr()).unwrap_or(Ipv4Addr::UNSPECIFIED);
        if is_martian_src(ip.src, own_ip) {
            return Ok(());
        }

        match ip.proto {
            IpProto::ICMP => {
                let icmp_buf = ip.payload(ip_buf);
                match IcmpMessage::parse(icmp_buf) {
                    Ok(IcmpMessage::EchoRequest { .. }) => {
                        // RFC 1122 §3.2.2.6: do not reply to echo requests
                        // sent to a broadcast address (Smurf amplification).
                        let is_bcast = ip.dst == Ipv4Addr::BROADCAST
                            || self.ip.is_some_and(|c| ip.dst == c.broadcast());
                        if is_bcast { return Ok(()); }
                        self.send_icmp_echo_reply(raw)?;
                    }
                    Ok(IcmpMessage::DestUnreach { code: 4, next_hop_mtu }) => {
                        // Fragmentation Needed (RFC 1191 §4): update MSS on the
                        // matching TCP socket.
                        let embedded = &icmp_buf[ICMP_HDR_LEN..];
                        if let Ok(orig_ip) = Ipv4Hdr::parse(embedded) {
                            let orig_tcp_buf = orig_ip.payload(embedded);
                            if orig_ip.proto == IpProto::TCP && orig_tcp_buf.len() >= 4 {
                                let orig_src_port =
                                    u16::from_be_bytes([orig_tcp_buf[0], orig_tcp_buf[1]]);
                                let orig_dst_port =
                                    u16::from_be_bytes([orig_tcp_buf[2], orig_tcp_buf[3]]);
                                let new_mss = next_hop_mtu.saturating_sub(
                                    IP_HDR_LEN as u16 + TCP_HDR_LEN as u16,
                                );
                                for s in tcp_sockets.iter_mut()
                                    .chain(standalone_tcp.iter_mut())
                                {
                                    if s.matches_flow(
                                        SocketAddrV4::new(orig_ip.src, orig_src_port),
                                        SocketAddrV4::new(orig_ip.dst, orig_dst_port),
                                    ) {
                                        s.update_pmtu(new_mss);
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            IpProto::UDP  => { udp::dispatch(self, raw, udp_sockets)?; }
            IpProto::TCP  => {
                let tcp_buf = ip.payload(ip_buf);
                if tcp_buf.len() >= 4 {
                    let dst_port = u16::from_be_bytes([tcp_buf[2], tcp_buf[3]]);
                    for s in standalone_tcp.iter_mut() {
                        if s.src_port() == dst_port {
                            let _ = s.process_segment(raw);
                            return Ok(());
                        }
                    }
                }
                tcp::dispatch(self, raw, tcp_sockets)?;
            }
            _ => {
                let _ = self.send_icmp_unreachable(raw, 2);
            }
        }
        Ok(())
    }

    // ── TX helpers (crate-visible for udp::dispatch / tcp::dispatch) ─────────

    /// Send an ARP Reply in response to an ARP Request targeting this interface.
    fn send_arp_reply(&self, req: &ArpHdr) -> Result<()> {
        let frame_len = ETH_HDR_LEN + ARP_HDR_LEN;
        let mut frame = [0u8; ETH_HDR_LEN + ARP_HDR_LEN];

        EthHdr { dst: req.sha, src: self.mac, ethertype: EtherType::ARP }
            .emit(&mut frame[..ETH_HDR_LEN])?;

        ArpHdr {
            oper: ArpOp::REPLY,
            sha:  self.mac,
            spa:  req.tpa,   // our IP (the address they were asking about)
            tha:  req.sha,
            tpa:  req.spa,
        }
        .emit(&mut frame[ETH_HDR_LEN..])?;

        (self.tx)(&frame[..frame_len])
    }

    /// Send an ICMP Echo Reply in response to an Echo Request.
    ///
    /// The reply preserves the original `id`, `seq`, and payload verbatim.
    /// Requests whose reply would exceed [`FRAME_SIZE`] are silently dropped.
    fn send_icmp_echo_reply(&mut self, raw: &[u8]) -> Result<()> {
        let cidr = self.ip.unwrap(); // guaranteed Some by callers

        let eth      = EthHdr::parse(raw)?;
        let ip_buf   = eth.payload(raw);
        let ip       = Ipv4Hdr::parse(ip_buf)?;
        let icmp_buf = ip.payload(ip_buf);
        let (id, seq) = match IcmpMessage::parse(icmp_buf) {
            Ok(IcmpMessage::EchoRequest { id, seq }) => (id, seq),
            _ => return Ok(()),
        };
        let payload = &icmp_buf[ICMP_HDR_LEN..];

        let frame_len = ETH_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN + payload.len();
        if frame_len > FRAME_SIZE {
            return Ok(());
        }

        let mut buf = [0u8; FRAME_SIZE];
        let frame   = &mut buf[..frame_len];

        EthHdr { dst: eth.src, src: self.mac, ethertype: EtherType::IPV4 }.emit(frame)?;

        self.tx_id = self.tx_id.wrapping_add(1);
        Ipv4Hdr {
            ihl:       5,
            dscp_ecn:  0,
            total_len: (IP_HDR_LEN + ICMP_HDR_LEN + payload.len()) as u16,
            id:        self.tx_id,
            flags_frag: 0,
            ttl:       64,
            proto:     IpProto::ICMP,
            src:       cidr.addr(),
            dst:       ip.src,
        }
        .emit(&mut frame[ETH_HDR_LEN..])?;

        let icmp_off = ETH_HDR_LEN + IP_HDR_LEN;
        IcmpMessage::EchoReply { id, seq }.emit(&mut frame[icmp_off..], payload)?;
        frame[icmp_off + ICMP_HDR_LEN..].copy_from_slice(payload);

        (self.tx)(frame)
    }

    /// Send ICMP Destination Unreachable (Type 3, `code`).
    ///
    /// Payload: original IP header + first 8 bytes of its payload (RFC 792).
    /// Subject to the per-interface ICMP rate limit; silently suppressed when
    /// the token bucket is empty.
    pub(crate) fn send_icmp_unreachable(
        &mut self,
        raw:  &[u8],
        code: u8,
    ) -> Result<()> {
        let now = self.clock.monotonic_ms();
        if !self.icmp_rl.allow(now) {
            return Ok(());
        }
        let cidr = self.ip.unwrap(); // guaranteed Some by callers

        let eth    = EthHdr::parse(raw)?;
        let ip_buf = eth.payload(raw);
        let ip     = Ipv4Hdr::parse(ip_buf)?;

        // Build ICMP payload on the stack: orig IP hdr + up to 8 payload bytes.
        let orig_hdr_len     = ip.hdr_len().min(ip_buf.len());
        let after_hdr        = &ip_buf[orig_hdr_len..];
        let suffix_len       = after_hdr.len().min(8);
        let icmp_payload_len = orig_hdr_len + suffix_len;
        let mut icmp_payload_buf = [0u8; 68]; // max IP hdr (60) + 8 bytes L4
        icmp_payload_buf[..orig_hdr_len].copy_from_slice(&ip_buf[..orig_hdr_len]);
        icmp_payload_buf[orig_hdr_len..icmp_payload_len]
            .copy_from_slice(&after_hdr[..suffix_len]);
        let icmp_payload = &icmp_payload_buf[..icmp_payload_len];

        let total_ip_len = (IP_HDR_LEN + ICMP_HDR_LEN + icmp_payload_len) as u16;
        let frame_len    = ETH_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN + icmp_payload_len;

        let mut buf   = [0u8; FRAME_SIZE];
        let frame     = &mut buf[..frame_len];

        EthHdr { dst: eth.src, src: self.mac, ethertype: EtherType::IPV4 }.emit(frame)?;

        self.tx_id = self.tx_id.wrapping_add(1);
        Ipv4Hdr {
            ihl: 5,
            dscp_ecn: 0,
            total_len: total_ip_len,
            id: self.tx_id,
            flags_frag: 0,
            ttl: 64,
            proto: IpProto::ICMP,
            src: cidr.addr(),
            dst: ip.src,
        }
        .emit(&mut frame[ETH_HDR_LEN..])?;

        let icmp_off = ETH_HDR_LEN + IP_HDR_LEN;
        IcmpMessage::DestUnreach { code, next_hop_mtu: 0 }
            .emit(&mut frame[icmp_off..], icmp_payload)?;
        frame[icmp_off + ICMP_HDR_LEN..icmp_off + ICMP_HDR_LEN + icmp_payload_len]
            .copy_from_slice(icmp_payload);

        (self.tx)(frame)
    }

    /// Send a TCP RST in response to an unexpected inbound segment.
    ///
    /// - Inbound has ACK set → RST with `seq = seg.ack`.
    /// - Otherwise → RST|ACK with `seq = 0, ack = seg.seq + seg_len`
    ///   (RFC 793 §3.4).
    pub(crate) fn send_tcp_rst(&mut self, raw: &[u8]) -> Result<()> {
        let cidr = self.ip.unwrap();

        let eth    = EthHdr::parse(raw)?;
        let ip_buf = eth.payload(raw);
        let ip     = Ipv4Hdr::parse(ip_buf)?;
        let tcp_buf = ip.payload(ip_buf);
        let seg    = TcpHdr::parse(tcp_buf)?;

        let frame_len = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
        let mut buf   = [0u8; FRAME_SIZE];
        let frame     = &mut buf[..frame_len];

        EthHdr { dst: eth.src, src: self.mac, ethertype: EtherType::IPV4 }.emit(frame)?;

        self.tx_id = self.tx_id.wrapping_add(1);
        Ipv4Hdr {
            ihl: 5,
            dscp_ecn: 0,
            total_len: (IP_HDR_LEN + TCP_HDR_LEN) as u16,
            id: self.tx_id,
            flags_frag: 0,
            ttl: 64,
            proto: IpProto::TCP,
            src: cidr.addr(),
            dst: ip.src,
        }
        .emit(&mut frame[ETH_HDR_LEN..])?;

        let tcp_off = ETH_HDR_LEN + IP_HDR_LEN;
        let (seq, ack_num, flags) = if seg.has_flag(TcpFlags::ACK) {
            (seg.ack, SeqNum::new(0), TcpFlags::RST)
        } else {
            // RFC 793 §3.4: ack = SEG.SEQ + SEG.LEN (payload + SYN/FIN).
            let payload_start = seg.hdr_len().min(tcp_buf.len());
            let payload_len   = tcp_buf.len().saturating_sub(payload_start) as u32;
            let syn_fin       = (seg.flags & (TcpFlags::SYN | TcpFlags::FIN)).bits().count_ones();
            let seg_len       = payload_len + syn_fin;
            (SeqNum::new(0), seg.seq + seg_len.max(1), TcpFlags::RST | TcpFlags::ACK)
        };
        TcpHdr {
            src_port:    seg.dst_port,
            dst_port:    seg.src_port,
            seq,
            ack:         ack_num,
            data_offset: 5,
            flags,
            window:      0,
            checksum:    0,
            urgent:      0,
        }
        .emit(&mut frame[tcp_off..], &cidr.addr(), &ip.src, &[])?;

        (self.tx)(frame)
    }
}

// ── Martian source address check ─────────────────────────────────────────────

/// Return `true` if `src` must never appear as a packet source address.
///
/// Filters:
/// - `0.0.0.0/8`  — "this" network (unspecified source)
/// - `127.0.0.0/8` — loopback
/// - `224.0.0.0/4` — multicast
/// - `240.0.0.0/4` — reserved / Class E
/// - `255.255.255.255` — limited broadcast
/// - `own_ip` — LAND attack (source == our own address)
#[inline]
fn is_martian_src(src: Ipv4Addr, own_ip: Ipv4Addr) -> bool {
    src.is_unspecified()   // 0.0.0.0/8
    || src.is_loopback()   // 127.0.0.0/8
    || src.is_multicast()  // 224.0.0.0/4
    || src.octets()[0] >= 240  // reserved / Class E (240.0.0.0/4) and broadcast
    || src.is_broadcast()
    || src == own_ip       // LAND attack
}

// ── Fragment purge timer ──────────────────────────────────────────────────────

/// Install a self-rescheduling 1-second timer that purges timed-out
/// reassembly entries on `reasm`.  This ensures memory is reclaimed even
/// when no new fragments arrive to trigger the on-insert purge.
fn schedule_frag_purge_inner(
    reasm: Rc<RefCell<ReassemblyTable>>,
    timers: &mut Timers,
) {
    timers.add(1_000, move |timers| {
        reasm.borrow_mut().purge();
        schedule_frag_purge_inner(reasm, timers);
    });
}
