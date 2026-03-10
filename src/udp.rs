/// UDP datagram encode / decode + checksum.
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddrV4};
use crate::{
    arp_cache::ArpQueue,
    eth::{EthHdr, MacAddr},
    interface::Interface,
    ip::{
        checksum_add, checksum_finish, pseudo_header_acc, IpProto, Ipv4Hdr,
        MIN_HDR_LEN as IP_HDR_LEN,
    },
    af_packet::FRAME_SIZE,
    timers::Timers,
    Error, Result,
};

/// Maximum UDP payload that fits in a single TPACKET_V2 frame.
///
/// FRAME_SIZE (65536) minus the Tpacket2Hdr overhead (32 bytes) minus the
/// combined Ethernet + IPv4 + UDP header size (42 bytes).
const MAX_UDP_PAYLOAD: usize = FRAME_SIZE - 32 - crate::eth::HDR_LEN - IP_HDR_LEN - HDR_LEN;

pub const HDR_LEN: usize = 8;

/// How long (ms) to keep a queued frame waiting for ARP resolution.
const ARP_TIMEOUT_MS: u64 = 1_000;

#[derive(Debug, Clone, Copy)]
pub struct UdpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub length:   u16,
    pub checksum: u16,
}

impl UdpHdr {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HDR_LEN {
            return Err(Error::InvalidData);
        }
        Ok(UdpHdr {
            src_port: u16::from_be_bytes([buf[0], buf[1]]),
            dst_port: u16::from_be_bytes([buf[2], buf[3]]),
            length:   u16::from_be_bytes([buf[4], buf[5]]),
            checksum: u16::from_be_bytes([buf[6], buf[7]]),
        })
    }

    /// Emit into `buf[0..8]` with checksum computed over `src_ip`/`dst_ip`
    /// pseudo-header and `payload`.
    pub fn emit(
        &self,
        buf: &mut [u8],
        src_ip:  &Ipv4Addr,
        dst_ip:  &Ipv4Addr,
        payload: &[u8],
    ) -> Result<()> {
        if buf.len() < HDR_LEN {
            return Err(Error::InvalidInput);
        }
        let length = (HDR_LEN + payload.len()) as u16;
        buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buf[4..6].copy_from_slice(&length.to_be_bytes());
        buf[6..8].copy_from_slice(&[0, 0]);

        let acc = pseudo_header_acc(src_ip, dst_ip, IpProto::UDP, length);
        let acc = checksum_add(acc, &buf[..HDR_LEN]);
        let acc = checksum_add(acc, payload);
        let csum = checksum_finish(acc);
        // RFC 768: computed zero is transmitted as 0xFFFF
        let csum = if csum == 0 { 0xffff } else { csum };
        buf[6..8].copy_from_slice(&csum.to_be_bytes());
        Ok(())
    }

    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[HDR_LEN..]
    }
}

// ── Packet delivery struct ────────────────────────────────────────────────────

/// Parsed addresses and payload reference delivered to a [`UdpSocket`] callback.
///
/// Valid only for the duration of the callback invocation.
pub struct UdpPacket<'a> {
    pub eth_src: MacAddr,
    pub eth_dst: MacAddr,
    pub src:     SocketAddrV4,
    pub dst:     SocketAddrV4,
    /// Layer-4 payload (the bytes after the UDP header).
    pub pdu: &'a [u8],
}

// ── Higher-level socket-like API ──────────────────────────────────────────────

pub struct UdpSocket {
    /// IP-level TX closure: takes (dst_ip, proto, payload) and handles
    /// Ethernet header construction, IPv4 header construction, and ARP
    /// resolution.  Provided by [`Interface::open_ip_tx`].
    ip_tx:     crate::IpTxFn,
    src:       SocketAddrV4,
    on_recv:   for<'a> fn(UdpPacket<'a>),
    /// Combined ARP cache + frame queue, shared with the owning interface.
    /// Used by [`send_to_now`] to check for a cached MAC (WouldBlock guard)
    /// and by [`send_to`] to detect the first-frame-for-IP transition so the
    /// ARP timeout timer can be scheduled.
    arp_queue: ArpQueue,
}

impl UdpSocket {
    /// Create a UDP socket.
    ///
    /// The socket shares the interface's ARP cache for MAC resolution.
    /// `on_recv` is called by [`dispatch`] whenever a datagram addressed to
    /// `src_port` arrives.  Pass `|_| {}` for a no-op.
    pub(crate) fn new(
        iface:   &Interface,
        src:     SocketAddrV4,
        on_recv: for<'a> fn(UdpPacket<'a>),
    ) -> Self {
        UdpSocket {
            ip_tx: iface.open_ip_tx(),
            src,
            on_recv,
            arp_queue: iface.arp_queue().clone(),
        }
    }

    pub fn src_port(&self) -> u16 { self.src.port() }

    /// Send `payload` to `dst_ip:dst_port`.
    ///
    /// `nexthop_ip` is the gateway IP for off-subnet destinations, or `dst_ip`
    /// for on-link destinations.  It is resolved via ARP; the IP header always
    /// carries `dst_ip` as the destination.
    ///
    /// If the nexthop MAC is in the ARP cache the datagram is sent immediately.
    /// Otherwise a complete frame (UDP header + payload wrapped in IP) is pushed
    /// into the interface-level ARP queue; [`Interface::receive`] will fill in
    /// the MAC and transmit the frame once ARP resolves.  A single ARP Request
    /// is broadcast per unresolved nexthop; concurrent datagrams to the same
    /// nexthop are all queued and flushed together.
    pub fn send_to(
        &mut self,
        payload:    &[u8],
        dst:        SocketAddrV4,
        nexthop_ip: Ipv4Addr,
        timers:     &mut Timers,
    ) -> Result<()> {
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(Error::InvalidInput);
        }
        let udp_bytes = self.build_udp(payload, *dst.ip(), dst.port());

        // Sample pending-queue depth before calling ip_tx so we can detect
        // the FirstForIp transition and schedule exactly one drop timer.
        let pending_before = self.arp_queue.pending_count_for(nexthop_ip);

        (self.ip_tx)(nexthop_ip, IpProto::UDP, 0, &udp_bytes)?;

        // Schedule a cleanup timer when this is the first queued frame for
        // this nexthop (mirrors the FirstForIp branch in the old send_to).
        if pending_before == 0 && self.arp_queue.pending_count_for(nexthop_ip) > 0 {
            let q = self.arp_queue.clone();
            timers.add(ARP_TIMEOUT_MS, move |_| q.drop_pending(nexthop_ip));
        }
        Ok(())
    }

    /// Send immediately using a MAC already known to the caller (FFI path).
    ///
    /// `nexthop_ip` is the gateway IP for off-subnet destinations, or `dst_ip`
    /// for on-link destinations.  Returns [`Error::WouldBlock`] if `nexthop_ip`
    /// is not in the ARP cache.
    pub(crate) fn send_to_now(
        &mut self,
        payload:    &[u8],
        dst:        SocketAddrV4,
        nexthop_ip: Ipv4Addr,
    ) -> Result<()> {
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(Error::InvalidInput);
        }
        // Guard: return WouldBlock if nexthop MAC is not yet cached.
        if self.arp_queue.lookup_and_refresh(nexthop_ip).is_none() {
            return Err(Error::WouldBlock);
        }
        let udp_bytes = self.build_udp(payload, *dst.ip(), dst.port());
        // ip_tx will find the MAC in cache (just refreshed above) and send.
        (self.ip_tx)(nexthop_ip, IpProto::UDP, 0, &udp_bytes)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Build a UDP header + payload byte vector.
    ///
    /// Returns `HDR_LEN + payload.len()` bytes with the checksum computed over
    /// the IPv4 pseudo-header `(src.ip(), dst_ip)`.
    fn build_udp(
        &self,
        payload:  &[u8],
        dst_ip:   Ipv4Addr,
        dst_port: u16,
    ) -> Vec<u8> {
        let udp_len = HDR_LEN + payload.len();
        let mut buf = alloc::vec![0u8; udp_len];
        UdpHdr {
            src_port: self.src.port(),
            dst_port,
            length:   udp_len as u16,
            checksum: 0,
        }
        .emit(&mut buf, self.src.ip(), &dst_ip, payload)
        .expect("buffer sized for UDP header");
        buf[HDR_LEN..].copy_from_slice(payload);
        buf
    }
}

// ── L4 dispatch ───────────────────────────────────────────────────────────────

/// Dispatch a UDP segment to the matching socket and invoke its callback.
///
/// Parses the UDP header from `raw` and scans `sockets` for a socket whose
/// `src_port` matches the datagram's destination port.  On a match the
/// socket's `on_recv` callback is called with a fully-populated [`UdpPacket`].
/// On no match, sends ICMP Destination Unreachable Type 3 Code 3 via `iface`.
pub fn dispatch(
    iface:   &mut Interface,
    raw:     &[u8],
    sockets: &mut [UdpSocket],
) -> Result<()> {
    let eth = EthHdr::parse(raw)?;
    let ip_buf = eth.payload(raw);
    // IP checksum validated by the interface layer before dispatch.
    let ip = Ipv4Hdr::parse_no_checksum(ip_buf)?;
    let udp_buf = ip.payload(ip_buf);
    let udp = UdpHdr::parse(udp_buf)?;

    // Checksum validation (off by default; enable for software-only paths).
    // RFC 768: checksum field = 0 means "no checksum computed" — skip.
    if iface.checksum_validate_udp && udp.checksum != 0 {
        let acc = pseudo_header_acc(&ip.src, &ip.dst, IpProto::UDP, udp.length);
        let acc = checksum_add(acc, udp_buf);
        if checksum_finish(acc) != 0 {
            return Ok(()); // bad checksum — silently drop
        }
    }

    for s in sockets.iter_mut() {
        if s.src_port() == udp.dst_port {
            let pdu = udp.payload(udp_buf);
            (s.on_recv)(UdpPacket {
                eth_src: eth.src,
                eth_dst: eth.dst,
                src:     SocketAddrV4::new(ip.src, udp.src_port),
                dst:     SocketAddrV4::new(ip.dst, udp.dst_port),
                pdu,
            });
            return Ok(());
        }
    }

    // No socket listening on this port — ICMP Port Unreachable.
    let _ = iface.send_icmp_unreachable(raw, 3);
    Ok(())
}
