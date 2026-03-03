/// UDP datagram encode / decode + checksum.
use alloc::{rc::Rc, vec::Vec};
use core::net::{Ipv4Addr, SocketAddrV4};
use crate::{
    arp_cache::{self, ArpQueue, PushResult},
    eth::{EthHdr, EtherType, MacAddr},
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
    tx:        crate::TxFn,
    src_mac:   MacAddr,
    src:       SocketAddrV4,
    tx_id:     u16,
    on_recv:   for<'a> fn(UdpPacket<'a>),
    /// Combined ARP cache + frame queue, shared with the owning interface.
    /// All MAC lookups and frame queuing go through this single handle.
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
            tx: iface.tx(),
            src_mac: iface.mac(),
            src,
            tx_id: 0,
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
    /// Otherwise the datagram is built into a complete Ethernet frame (with a
    /// zeroed dst MAC as placeholder) and pushed into the interface-level ARP
    /// queue; [`Interface::receive`] will fill in the MAC and transmit the
    /// frame once ARP resolves.  A single ARP Request is broadcast per
    /// unresolved nexthop; concurrent datagrams to the same nexthop are all
    /// queued and flushed together.
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
        let frame = self.build_frame_vec(payload, *dst.ip(), dst.port());
        match self.arp_queue.push_frame(nexthop_ip, frame) {
            PushResult::Sent(f) => (self.tx)(&f),
            PushResult::Queued  => Ok(()),
            PushResult::FirstForIp => {
                let tx = Rc::clone(&self.tx);
                arp_cache::send_request(self.src_mac, *self.src.ip(), nexthop_ip, |f| tx(f))?;
                let q = self.arp_queue.clone();
                timers.add(ARP_TIMEOUT_MS, move |_| q.drop_pending(nexthop_ip));
                Ok(())
            }
        }
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
        match self.arp_queue.lookup_and_refresh(nexthop_ip) {
            Some(dst_mac) => self.send_frame(payload, *dst.ip(), dst.port(), dst_mac),
            None          => Err(Error::WouldBlock),
        }
    }

    // ── Private frame builders ────────────────────────────────────────────────

    /// Fill `frame` with a complete Ethernet + IPv4 + UDP frame.
    ///
    /// `frame` must be exactly `eth::HDR_LEN + IP_HDR_LEN + HDR_LEN + payload.len()` bytes.
    fn fill_frame(
        &mut self,
        frame:    &mut [u8],
        dst_ip:   Ipv4Addr,
        dst_port: u16,
        dst_mac:  MacAddr,
        payload:  &[u8],
    ) -> Result<()> {
        let total_ip_len = (IP_HDR_LEN + HDR_LEN + payload.len()) as u16;
        EthHdr { dst: dst_mac, src: self.src_mac, ethertype: EtherType::IPV4 }.emit(frame)?;
        self.tx_id = self.tx_id.wrapping_add(1);
        Ipv4Hdr {
            ihl: 5, dscp_ecn: 0, total_len: total_ip_len,
            id: self.tx_id, flags_frag: 0x4000, ttl: 64,
            proto: IpProto::UDP, src: *self.src.ip(), dst: dst_ip,
        }.emit(&mut frame[crate::eth::HDR_LEN..])?;
        let udp_off = crate::eth::HDR_LEN + IP_HDR_LEN;
        UdpHdr { src_port: self.src.port(), dst_port,
                 length: (HDR_LEN + payload.len()) as u16, checksum: 0 }
            .emit(&mut frame[udp_off..], self.src.ip(), &dst_ip, payload)?;
        frame[udp_off + HDR_LEN..].copy_from_slice(payload);
        Ok(())
    }

    fn build_frame_vec(
        &mut self,
        payload:  &[u8],
        dst_ip:   Ipv4Addr,
        dst_port: u16,
    ) -> Vec<u8> {
        let frame_len = crate::eth::HDR_LEN + IP_HDR_LEN + HDR_LEN + payload.len();
        let mut frame = alloc::vec![0u8; frame_len];
        self.fill_frame(&mut frame, dst_ip, dst_port, MacAddr::ZERO, payload)
            .expect("buffer sized for frame");
        frame
    }

    fn send_frame(
        &mut self,
        payload:  &[u8],
        dst_ip:   Ipv4Addr,
        dst_port: u16,
        dst_mac:  MacAddr,
    ) -> Result<()> {
        let frame_len = crate::eth::HDR_LEN + IP_HDR_LEN + HDR_LEN + payload.len();
        let mut frame = alloc::vec![0u8; frame_len];
        self.fill_frame(&mut frame, dst_ip, dst_port, dst_mac, payload)?;
        (self.tx)(&frame)
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
    let ip = Ipv4Hdr::parse(ip_buf)?;
    let udp_buf = ip.payload(ip_buf);
    let udp = UdpHdr::parse(udp_buf)?;

    // NOTE: no UDP checksum validation here.  Same rationale as TCP: the
    // kernel / NIC hardware has already verified the checksum before the
    // frame reaches our AF_PACKET TPACKET_V2 ring.  GRO/LRO-combined
    // frames would fail a re-check because the header carries only the
    // first segment's checksum.

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
