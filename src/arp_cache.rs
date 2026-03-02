/// ARP cache, outbound frame queue, and expiry scheduling — all per-interface.
///
/// [`ArpCache`] is the raw TTL-keyed map.  [`ArpQueue`] wraps it together with
/// the queue of outbound frames waiting for MAC resolution; a single clone of
/// `ArpQueue` is handed to every socket created on an interface so that
/// sockets can look up MACs and queue frames without knowing about the
/// interface directly.  [`schedule_expiry`] installs a self-rescheduling timer
/// that purges stale cache entries.
use alloc::{rc::Rc, vec::Vec};
use core::cell::{Cell, RefCell};
use crate::{
    arp::{ArpHdr, HDR_LEN as ARP_HDR_LEN, OPER_REQUEST},
    eth::{EthHdr, MacAddr, HDR_LEN as ETH_HDR_LEN, ETHERTYPE_ARP},
    packet_socket::PacketSocket,
    timers::{now_ms, Timers},
    Result,
};

// ── Entry ─────────────────────────────────────────────────────────────────────

pub struct ArpEntry {
    pub ip:  [u8; 4],
    pub mac: MacAddr,
    /// Absolute monotonic timestamp (ms) after which this entry is stale.
    expires_at: u64,
}

// ── Cache ─────────────────────────────────────────────────────────────────────

pub struct ArpCache {
    entries: Vec<ArpEntry>,
    /// Maximum lifetime of a cache entry in milliseconds.
    /// Also used as the interval between expiry timer firings.
    pub max_age_ms: u64,
    /// Maximum number of entries.  When the cache is full and a new IP is
    /// seen, the oldest entry (entries[0]) is evicted (FIFO).  Default: 256.
    pub max_entries: usize,
}

impl ArpCache {
    pub fn new(max_age_ms: u64) -> Self {
        ArpCache { entries: Vec::new(), max_age_ms, max_entries: 256 }
    }

    /// Insert or refresh the MAC address for `ip`.
    ///
    /// If an entry for `ip` already exists it is updated in place; otherwise
    /// a new entry is appended.  When the cache is full, the oldest entry
    /// (FIFO) is evicted to make room.  The expiry is set to `now + max_age_ms`.
    pub fn insert(&mut self, ip: [u8; 4], mac: MacAddr) {
        let expires_at = now_ms() + self.max_age_ms;
        if let Some(e) = self.entries.iter_mut().find(|e| e.ip == ip) {
            e.mac = mac;
            e.expires_at = expires_at;
        } else {
            // Evict the oldest entry (index 0) when at capacity.
            if self.entries.len() >= self.max_entries {
                self.entries.remove(0);
            }
            self.entries.push(ArpEntry { ip, mac, expires_at });
        }
    }

    /// Return the cached MAC address for `ip`, or `None` if not present or
    /// expired.
    pub fn lookup(&self, ip: [u8; 4]) -> Option<MacAddr> {
        let now = now_ms();
        self.entries
            .iter()
            .find(|e| e.ip == ip && e.expires_at > now)
            .map(|e| e.mac)
    }

    /// Like [`lookup`](Self::lookup), but also extends the entry's expiry to
    /// `now + max_age_ms` on a hit, preventing frequently-used entries from
    /// aging out while traffic is flowing.
    pub fn lookup_and_refresh(&mut self, ip: [u8; 4]) -> Option<MacAddr> {
        let now = now_ms();
        if let Some(e) = self.entries.iter_mut().find(|e| e.ip == ip && e.expires_at > now) {
            e.expires_at = now + self.max_age_ms;
            Some(e.mac)
        } else {
            None
        }
    }

    /// Remove all entries whose expiry timestamp has passed.
    ///
    /// Called automatically by the timer installed via [`schedule_expiry`].
    pub fn expire(&mut self) {
        let now = now_ms();
        self.entries.retain(|e| e.expires_at > now);
    }
}

// ── ArpQueue ──────────────────────────────────────────────────────────────────

/// A complete Ethernet frame waiting for its destination MAC to be resolved.
/// Bytes `[0..6]` are zeroed as a placeholder; [`ArpQueue::drain_for`] fills
/// them in once ARP resolves.
pub(crate) struct ArpQueueEntry {
    pub dst_ip: [u8; 4],
    pub frame:  Vec<u8>,
}

/// Inner state of the outbound-frame queue shared across `ArpQueue` clones.
struct PendingQueue {
    entries:    Vec<ArpQueueEntry>,
    /// Maximum frames that may be queued for a single unresolved destination
    /// IP.  Frames beyond this limit are silently dropped.  Default: 4.
    max_per_ip: usize,
}

/// Return value of [`ArpQueue::push_frame`].
pub(crate) enum PushResult {
    /// MAC was in the cache.  The frame has its dst MAC filled in and is ready
    /// to transmit; the caller should call `sock.tx_send`.
    Sent(Vec<u8>),
    /// Frame queued.  An ARP Request for `dst_ip` is already in flight
    /// (another frame for the same IP is already in the queue).
    Queued,
    /// Frame queued.  This is the *first* frame for `dst_ip` — the caller must
    /// broadcast an ARP Request and install a drop timer.
    FirstForIp,
}

/// Combined ARP cache + outbound-frame queue for one interface.
///
/// Both halves are stored behind `Rc<RefCell<>>` so a cheap `clone()` can be
/// given to each socket; all clones share the same live state.
pub(crate) struct ArpQueue {
    cache:   Rc<RefCell<ArpCache>>,
    pending: Rc<RefCell<PendingQueue>>,
    /// Set to `false` by [`mark_dead`] when the owning interface is detached.
    /// The self-rescheduling expiry timer checks this flag and stops firing.
    alive:   Rc<Cell<bool>>,
}

impl Clone for ArpQueue {
    fn clone(&self) -> Self {
        ArpQueue {
            cache:   Rc::clone(&self.cache),
            pending: Rc::clone(&self.pending),
            alive:   Rc::clone(&self.alive),
        }
    }
}

impl ArpQueue {
    pub fn new(max_age_ms: u64) -> Self {
        ArpQueue {
            cache:   Rc::new(RefCell::new(ArpCache::new(max_age_ms))),
            pending: Rc::new(RefCell::new(PendingQueue { entries: Vec::new(), max_per_ip: 4 })),
            alive:   Rc::new(Cell::new(true)),
        }
    }

    /// Called when the owning interface is detached from the uplink.
    ///
    /// Clears all queued outbound frames and prevents the self-rescheduling
    /// expiry timer from firing again — stopping a resource leak of timer slots.
    pub fn mark_dead(&self) {
        self.alive.set(false);
        self.pending.borrow_mut().entries.clear();
    }

    pub fn set_max_age_ms(&self, ms: u64) {
        self.cache.borrow_mut().max_age_ms = ms;
    }

    pub fn max_age_ms(&self) -> u64 {
        self.cache.borrow().max_age_ms
    }

    /// Set the maximum number of ARP cache entries.  When the cache is full,
    /// the oldest entry is evicted (FIFO) to make room.  Default: 256.
    pub fn set_max_entries(&self, n: usize) {
        self.cache.borrow_mut().max_entries = n;
    }

    /// Set the maximum number of queued frames per unresolved destination IP.
    /// Frames beyond this limit are silently dropped.  Default: 4.
    pub fn set_max_pending_per_ip(&self, n: usize) {
        self.pending.borrow_mut().max_per_ip = n;
    }

    /// Insert or refresh a cache entry (called on ARP receipt).
    pub fn insert(&self, ip: [u8; 4], mac: MacAddr) {
        self.cache.borrow_mut().insert(ip, mac);
    }

    /// Purge expired entries (called by the recurring timer).
    pub fn expire(&self) {
        self.cache.borrow_mut().expire();
    }

    /// Look up `ip` without extending its TTL.
    pub fn lookup(&self, ip: [u8; 4]) -> Option<MacAddr> {
        self.cache.borrow().lookup(ip)
    }

    /// Look up `ip` and extend its TTL on a hit.
    pub fn lookup_and_refresh(&self, ip: [u8; 4]) -> Option<MacAddr> {
        self.cache.borrow_mut().lookup_and_refresh(ip)
    }

    /// Try to route `frame` to `dst_ip`:
    ///
    /// - **MAC cached** → fills bytes `[0..6]` and returns [`PushResult::Sent`].
    /// - **Already queued, under limit** → appends and returns [`PushResult::Queued`].
    /// - **Already queued, at limit** → drops frame, returns [`PushResult::Queued`].
    /// - **First for IP** → appends and returns [`PushResult::FirstForIp`];
    ///   the caller must send an ARP Request and add a drop timer.
    pub fn push_frame(&self, dst_ip: [u8; 4], mut frame: Vec<u8>) -> PushResult {
        if let Some(mac) = self.cache.borrow_mut().lookup_and_refresh(dst_ip) {
            frame[0..6].copy_from_slice(&mac);
            return PushResult::Sent(frame);
        }
        let mut pending = self.pending.borrow_mut();
        let count = pending.entries.iter().filter(|e| e.dst_ip == dst_ip).count();
        if count == 0 {
            pending.entries.push(ArpQueueEntry { dst_ip, frame });
            PushResult::FirstForIp
        } else if count < pending.max_per_ip {
            pending.entries.push(ArpQueueEntry { dst_ip, frame });
            PushResult::Queued
        } else {
            // Per-IP queue full; silently drop the frame.
            PushResult::Queued
        }
    }

    /// Remove all queued frames for `dst_ip`, fill in `mac`, and return them
    /// ready to transmit.  Called by [`Interface::receive`] on ARP resolution.
    pub fn drain_for(&self, dst_ip: [u8; 4], mac: MacAddr) -> Vec<Vec<u8>> {
        let mut pending = self.pending.borrow_mut();
        let mut out = Vec::new();
        let mut i = 0;
        while i < pending.entries.len() {
            if pending.entries[i].dst_ip == dst_ip {
                let mut e = pending.entries.remove(i);
                e.frame[0..6].copy_from_slice(&mac);
                out.push(e.frame);
            } else {
                i += 1;
            }
        }
        out
    }

    /// Drop all queued frames for `dst_ip`.  Called by the ARP timeout timer.
    pub fn drop_pending(&self, dst_ip: [u8; 4]) {
        self.pending.borrow_mut().entries.retain(|e| e.dst_ip != dst_ip);
    }
}

// ── ARP request ───────────────────────────────────────────────────────────────

/// Broadcast an ARP Request asking who has `dst_ip`, tell `src_ip`.
///
/// The request is sent on `sock` as a link-layer broadcast.  The reply (if
/// any) arrives on the shared uplink socket and is handled by
/// [`Interface::receive`](crate::interface::Interface::receive).
pub fn send_request(
    src_mac: MacAddr,
    src_ip:  [u8; 4],
    dst_ip:  [u8; 4],
    sock:    &mut PacketSocket,
) -> Result<()> {
    let frame_len = ETH_HDR_LEN + ARP_HDR_LEN;
    let mut buf = [0u8; 64];
    let frame = &mut buf[..frame_len];

    EthHdr { dst: [0xff; 6], src: src_mac, ethertype: ETHERTYPE_ARP }.emit(frame)?;
    ArpHdr {
        oper: OPER_REQUEST,
        sha:  src_mac,
        spa:  src_ip,
        tha:  [0u8; 6],
        tpa:  dst_ip,
    }
    .emit(&mut frame[ETH_HDR_LEN..])?;

    sock.tx_send(frame)
}

// ── Recurring expiry timer ────────────────────────────────────────────────────

/// Install a self-rescheduling expiry timer on `arp`.
///
/// The timer fires every `arp.max_age_ms()` milliseconds, calls
/// [`ArpQueue::expire`] to purge stale entries, then re-adds itself.
/// Stops rescheduling once [`ArpQueue::mark_dead`] has been called (i.e.
/// after the owning interface is detached).
pub(crate) fn schedule_expiry(arp: ArpQueue, timers: &mut Timers) {
    let interval_ms = arp.max_age_ms();
    timers.add(interval_ms, move |timers| {
        if !arp.alive.get() { return; }   // interface detached; stop
        arp.expire();
        schedule_expiry(arp, timers);
    });
}
