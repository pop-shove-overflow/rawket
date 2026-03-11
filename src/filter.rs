//! Packet filter expressions for use in [`PacketSpec`](crate::bridge::PacketSpec).
//!
//! Filters describe which Ethernet frames should match an impairment or
//! capture rule.  They compose with Rust's `&`, `|`, and `!` operators:
//!
//! ```rust,ignore
//! use rawket::filter::{tcp, ip};
//!
//! let f = tcp::syn() & !tcp::ack();           // SYN-only (no ACK)
//! let rst_or_fin = tcp::rst() | tcp::fin();   // RST or FIN
//! let from_host = ip::src("10.0.0.1".parse().unwrap());
//! ```

use core::net::Ipv4Addr;
use core::ops::{BitAnd, BitOr, Not};
use crate::eth::MacAddr;
use crate::ip::Ipv4Cidr;

// ── CmpOp ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CmpOp {
    fn apply_u8(self, a: u8, b: u8) -> bool {
        match self {
            CmpOp::Eq => a == b,
            CmpOp::Ne => a != b,
            CmpOp::Lt => a < b,
            CmpOp::Le => a <= b,
            CmpOp::Gt => a > b,
            CmpOp::Ge => a >= b,
        }
    }

    fn apply_u16(self, a: u16, b: u16) -> bool {
        match self {
            CmpOp::Eq => a == b,
            CmpOp::Ne => a != b,
            CmpOp::Lt => a < b,
            CmpOp::Le => a <= b,
            CmpOp::Gt => a > b,
            CmpOp::Ge => a >= b,
        }
    }

    fn apply_usize(self, a: usize, b: usize) -> bool {
        match self {
            CmpOp::Eq => a == b,
            CmpOp::Ne => a != b,
            CmpOp::Lt => a < b,
            CmpOp::Le => a <= b,
            CmpOp::Gt => a > b,
            CmpOp::Ge => a >= b,
        }
    }
}

// ── Filter ────────────────────────────────────────────────────────────────────

/// A composable packet filter expression.
///
/// Build filters using the helper functions in submodules ([`tcp`], [`udp`],
/// [`ip`], [`eth`], [`arp`]) and compose them with `&`, `|`, and `!`.
pub enum Filter {
    // Ethernet
    EtherSrc(MacAddr),
    EtherDst(MacAddr),
    EtherProto(u16),

    // VLAN
    Vlan(u16),
    AnyVlan,

    // IP
    SrcHost(Ipv4Addr),
    DstHost(Ipv4Addr),
    SrcNet(Ipv4Cidr),
    DstNet(Ipv4Cidr),

    // IP misc
    IpProto(u8),
    IpLen { op: CmpOp, n: u16 },
    IpTtl { op: CmpOp, n: u8 },
    IpFragment,
    IpDf,
    IpMf,

    // Transport protocol shortcuts
    Tcp,
    Udp,
    Icmp,
    Arp,
    Sctp,

    // Ports (TCP or UDP)
    SrcPort(u16),
    DstPort(u16),
    Port(u16),
    SrcPortRange(u16, u16),
    DstPortRange(u16, u16),
    PortRange(u16, u16),

    // TCP payload
    TcpPayloadLen { op: CmpOp, n: usize },

    // TCP flags
    TcpFlagSyn,
    TcpFlagAck,
    TcpFlagFin,
    TcpFlagRst,
    TcpFlagPsh,
    TcpFlagUrg,
    TcpFlagEce,
    TcpFlagCwr,
    TcpFlags { mask: u8, value: u8 },

    // Length
    Len { op: CmpOp, n: usize },

    // Raw byte access
    ByteAt { offset: usize, op: CmpOp, value: u8 },

    // Layer 2 special
    Broadcast,
    Multicast,

    // Boolean
    True,
    False,

    // Combinators
    And(Box<Filter>, Box<Filter>),
    Or(Box<Filter>, Box<Filter>),
    Not(Box<Filter>),
}

impl Filter {
    /// Returns `true` if `frame` matches this filter expression.
    pub fn matches(&self, frame: &[u8]) -> bool {
        use etherparse::SlicedPacket;
        // Parse lazily but we need owned data — parse once outside match if needed.
        // We use a closure to lazily parse so that simple cases (Len, ByteAt, True/False)
        // don't pay for etherparse.
        match self {
            // ── Quick cases that don't need parsing ──────────────────────────
            Filter::True => return true,
            Filter::False => return false,
            Filter::Len { op, n } => return op.apply_usize(frame.len(), *n),
            Filter::ByteAt { offset, op, value } => {
                return frame.get(*offset).is_some_and(|b| op.apply_u8(*b, *value));
            }
            Filter::Broadcast => {
                return frame.len() >= 6 && frame[0..6] == [0xff; 6];
            }
            Filter::Multicast => {
                if frame.len() < 6 { return false; }
                let is_mc = frame[0] & 1 != 0;
                let is_bc = frame[0..6] == [0xff; 6];
                return is_mc && !is_bc;
            }
            // ── Combinators ──────────────────────────────────────────────────
            Filter::And(a, b) => return a.matches(frame) && b.matches(frame),
            Filter::Or(a, b)  => return a.matches(frame) || b.matches(frame),
            Filter::Not(f)    => return !f.matches(frame),
            _ => {}
        }

        // Parse the frame with etherparse.
        let Ok(pkt) = SlicedPacket::from_ethernet(frame) else {
            // For protocol-specific filters, no-parse means no-match.
            return false;
        };

        match self {
            Filter::EtherSrc(mac) => {
                if let Some(etherparse::LinkSlice::Ethernet2(ref eth)) = pkt.link {
                    eth.source() == mac.octets()
                } else {
                    false
                }
            }
            Filter::EtherDst(mac) => {
                if let Some(etherparse::LinkSlice::Ethernet2(ref eth)) = pkt.link {
                    eth.destination() == mac.octets()
                } else {
                    false
                }
            }
            Filter::EtherProto(proto) => {
                // Check the outermost EtherType (after any VLAN tags).
                // Walk link_exts for the innermost ether_type.
                if let Some(last_ext) = pkt.link_exts.last() {
                    if let Some(ep) = last_ext.ether_payload() {
                        return ep.ether_type.0 == *proto;
                    }
                }
                if let Some(etherparse::LinkSlice::Ethernet2(ref eth)) = pkt.link {
                    eth.ether_type().0 == *proto
                } else {
                    false
                }
            }
            Filter::Vlan(id) => {
                pkt.vlan_ids().iter().any(|v| v.value() == *id)
            }
            Filter::AnyVlan => {
                !pkt.vlan_ids().is_empty()
            }

            // ── IP ────────────────────────────────────────────────────────────
            Filter::SrcHost(addr) => {
                if let Some(etherparse::NetSlice::Ipv4(ref ip)) = pkt.net {
                    Ipv4Addr::from(ip.header().source()) == *addr
                } else {
                    false
                }
            }
            Filter::DstHost(addr) => {
                if let Some(etherparse::NetSlice::Ipv4(ref ip)) = pkt.net {
                    Ipv4Addr::from(ip.header().destination()) == *addr
                } else {
                    false
                }
            }
            Filter::SrcNet(cidr) => {
                if let Some(etherparse::NetSlice::Ipv4(ref ip)) = pkt.net {
                    cidr.contains(Ipv4Addr::from(ip.header().source()))
                } else {
                    false
                }
            }
            Filter::DstNet(cidr) => {
                if let Some(etherparse::NetSlice::Ipv4(ref ip)) = pkt.net {
                    cidr.contains(Ipv4Addr::from(ip.header().destination()))
                } else {
                    false
                }
            }
            Filter::IpProto(proto) => {
                if let Some(etherparse::NetSlice::Ipv4(ref ip)) = pkt.net {
                    ip.header().protocol().0 == *proto
                } else {
                    false
                }
            }
            Filter::IpLen { op, n } => {
                if let Some(etherparse::NetSlice::Ipv4(ref ip)) = pkt.net {
                    op.apply_u16(ip.header().total_len(), *n)
                } else {
                    false
                }
            }
            Filter::IpTtl { op, n } => {
                if let Some(etherparse::NetSlice::Ipv4(ref ip)) = pkt.net {
                    op.apply_u8(ip.header().ttl(), *n)
                } else {
                    false
                }
            }
            Filter::IpFragment => {
                if let Some(etherparse::NetSlice::Ipv4(ref ip)) = pkt.net {
                    let hdr = ip.header();
                    hdr.more_fragments() || hdr.fragments_offset() != etherparse::IpFragOffset::ZERO
                } else {
                    false
                }
            }
            Filter::IpDf => {
                if let Some(etherparse::NetSlice::Ipv4(ref ip)) = pkt.net {
                    ip.header().dont_fragment()
                } else {
                    false
                }
            }
            Filter::IpMf => {
                if let Some(etherparse::NetSlice::Ipv4(ref ip)) = pkt.net {
                    ip.header().more_fragments()
                } else {
                    false
                }
            }

            // ── Protocol shortcuts ────────────────────────────────────────────
            Filter::Tcp => matches!(pkt.transport, Some(etherparse::TransportSlice::Tcp(_))),
            Filter::Udp => matches!(pkt.transport, Some(etherparse::TransportSlice::Udp(_))),
            Filter::Icmp => matches!(
                pkt.transport,
                Some(etherparse::TransportSlice::Icmpv4(_))
            ),
            Filter::Arp => {
                // ARP frames have EtherType 0x0806 and no IP layer.
                if let Some(etherparse::LinkSlice::Ethernet2(ref eth)) = pkt.link {
                    eth.ether_type().0 == 0x0806
                } else {
                    false
                }
            }
            Filter::Sctp => {
                // SCTP: IP protocol 132 (0x84)
                if let Some(etherparse::NetSlice::Ipv4(ref ip)) = pkt.net {
                    ip.header().protocol().0 == 132
                } else {
                    false
                }
            }

            // ── Ports ─────────────────────────────────────────────────────────
            Filter::SrcPort(p) => get_src_port(&pkt) == Some(*p),
            Filter::DstPort(p) => get_dst_port(&pkt) == Some(*p),
            Filter::Port(p) => {
                get_src_port(&pkt) == Some(*p) || get_dst_port(&pkt) == Some(*p)
            }
            Filter::SrcPortRange(lo, hi) => {
                get_src_port(&pkt).is_some_and(|s| s >= *lo && s <= *hi)
            }
            Filter::DstPortRange(lo, hi) => {
                get_dst_port(&pkt).is_some_and(|d| d >= *lo && d <= *hi)
            }
            Filter::PortRange(lo, hi) => {
                get_src_port(&pkt).is_some_and(|s| s >= *lo && s <= *hi)
                    || get_dst_port(&pkt).is_some_and(|d| d >= *lo && d <= *hi)
            }

            // ── TCP flags ─────────────────────────────────────────────────────
            Filter::TcpFlagSyn => tcp_flag(&pkt, |t| t.syn()),
            Filter::TcpFlagAck => tcp_flag(&pkt, |t| t.ack()),
            Filter::TcpFlagFin => tcp_flag(&pkt, |t| t.fin()),
            Filter::TcpFlagRst => tcp_flag(&pkt, |t| t.rst()),
            Filter::TcpFlagPsh => tcp_flag(&pkt, |t| t.psh()),
            Filter::TcpFlagUrg => tcp_flag(&pkt, |t| t.urg()),
            Filter::TcpFlagEce => tcp_flag(&pkt, |t| t.ece()),
            Filter::TcpFlagCwr => tcp_flag(&pkt, |t| t.cwr()),
            Filter::TcpFlags { mask, value } => {
                if let Some(etherparse::TransportSlice::Tcp(ref tcp)) = pkt.transport {
                    let flags: u8 = (tcp.fin() as u8)
                        | ((tcp.syn() as u8) << 1)
                        | ((tcp.rst() as u8) << 2)
                        | ((tcp.psh() as u8) << 3)
                        | ((tcp.ack() as u8) << 4)
                        | ((tcp.urg() as u8) << 5)
                        | ((tcp.ece() as u8) << 6)
                        | ((tcp.cwr() as u8) << 7);
                    (flags & mask) == *value
                } else {
                    false
                }
            }

            Filter::TcpPayloadLen { op, n } => {
                if let Some(etherparse::TransportSlice::Tcp(ref tcp)) = pkt.transport {
                    op.apply_usize(tcp.payload().len(), *n)
                } else {
                    false
                }
            }

            // Already handled above; unreachable here.
            Filter::True | Filter::False | Filter::Len { .. }
            | Filter::ByteAt { .. } | Filter::Broadcast | Filter::Multicast
            | Filter::And(_, _) | Filter::Or(_, _) | Filter::Not(_) => unreachable!(),
        }
    }
}

// ── Helper functions ──────────────────────────────────────────────────────────

fn get_src_port(pkt: &etherparse::SlicedPacket<'_>) -> Option<u16> {
    match &pkt.transport {
        Some(etherparse::TransportSlice::Tcp(t)) => Some(t.source_port()),
        Some(etherparse::TransportSlice::Udp(u)) => Some(u.source_port()),
        _ => None,
    }
}

fn get_dst_port(pkt: &etherparse::SlicedPacket<'_>) -> Option<u16> {
    match &pkt.transport {
        Some(etherparse::TransportSlice::Tcp(t)) => Some(t.destination_port()),
        Some(etherparse::TransportSlice::Udp(u)) => Some(u.destination_port()),
        _ => None,
    }
}

fn tcp_flag<F: Fn(&etherparse::TcpSlice<'_>) -> bool>(
    pkt: &etherparse::SlicedPacket<'_>,
    f: F,
) -> bool {
    if let Some(etherparse::TransportSlice::Tcp(ref tcp)) = pkt.transport {
        f(tcp)
    } else {
        false
    }
}

// ── Operator overloading ──────────────────────────────────────────────────────

impl BitAnd for Filter {
    type Output = Filter;
    fn bitand(self, rhs: Filter) -> Filter {
        Filter::And(Box::new(self), Box::new(rhs))
    }
}

impl BitOr for Filter {
    type Output = Filter;
    fn bitor(self, rhs: Filter) -> Filter {
        Filter::Or(Box::new(self), Box::new(rhs))
    }
}

impl Not for Filter {
    type Output = Filter;
    fn not(self) -> Filter {
        Filter::Not(Box::new(self))
    }
}

// ── Convenience submodules ────────────────────────────────────────────────────

pub mod tcp {
    use super::{CmpOp, Filter};

    /// Match TCP frames that carry a payload (payload length > 0).
    pub fn has_data() -> Filter { Filter::TcpPayloadLen { op: CmpOp::Gt, n: 0 } }
    /// Match TCP frames whose payload length equals `n` exactly.
    pub fn has_data_len(n: usize) -> Filter { Filter::TcpPayloadLen { op: CmpOp::Eq, n } }

    pub fn syn() -> Filter { Filter::TcpFlagSyn }
    pub fn ack() -> Filter { Filter::TcpFlagAck }
    pub fn fin() -> Filter { Filter::TcpFlagFin }
    pub fn rst() -> Filter { Filter::TcpFlagRst }
    pub fn psh() -> Filter { Filter::TcpFlagPsh }
    pub fn urg() -> Filter { Filter::TcpFlagUrg }
    pub fn ece() -> Filter { Filter::TcpFlagEce }
    pub fn cwr() -> Filter { Filter::TcpFlagCwr }
    pub fn src_port(p: u16) -> Filter { Filter::SrcPort(p) }
    pub fn dst_port(p: u16) -> Filter { Filter::DstPort(p) }
    pub fn port(p: u16) -> Filter { Filter::Port(p) }
    pub fn flags(mask: u8, value: u8) -> Filter { Filter::TcpFlags { mask, value } }
    pub fn only() -> Filter { Filter::Tcp }
}

pub mod udp {
    use super::Filter;

    pub fn src_port(p: u16) -> Filter { Filter::SrcPort(p) }
    pub fn dst_port(p: u16) -> Filter { Filter::DstPort(p) }
    pub fn port(p: u16) -> Filter { Filter::Port(p) }
    pub fn only() -> Filter { Filter::Udp }
}

pub mod ip {
    use core::net::Ipv4Addr;
    use crate::ip::Ipv4Cidr;
    use super::{CmpOp, Filter};

    pub fn src(addr: Ipv4Addr) -> Filter { Filter::SrcHost(addr) }
    pub fn dst(addr: Ipv4Addr) -> Filter { Filter::DstHost(addr) }
    pub fn src_net(cidr: Ipv4Cidr) -> Filter { Filter::SrcNet(cidr) }
    pub fn dst_net(cidr: Ipv4Cidr) -> Filter { Filter::DstNet(cidr) }
    pub fn proto(p: u8) -> Filter { Filter::IpProto(p) }
    pub fn ttl_eq(n: u8) -> Filter { Filter::IpTtl { op: CmpOp::Eq, n } }
    pub fn ttl_lt(n: u8) -> Filter { Filter::IpTtl { op: CmpOp::Lt, n } }
    pub fn len_eq(n: u16) -> Filter { Filter::IpLen { op: CmpOp::Eq, n } }
    pub fn len_gt(n: u16) -> Filter { Filter::IpLen { op: CmpOp::Gt, n } }
    pub fn fragment() -> Filter { Filter::IpFragment }
    pub fn df() -> Filter { Filter::IpDf }
    pub fn mf() -> Filter { Filter::IpMf }
}

pub mod eth {
    use crate::eth::MacAddr;
    use super::Filter;

    pub fn src(mac: MacAddr) -> Filter { Filter::EtherSrc(mac) }
    pub fn dst(mac: MacAddr) -> Filter { Filter::EtherDst(mac) }
    pub fn proto(p: u16) -> Filter { Filter::EtherProto(p) }
    pub fn broadcast() -> Filter { Filter::Broadcast }
    pub fn multicast() -> Filter { Filter::Multicast }
    pub fn vlan(id: u16) -> Filter { Filter::Vlan(id) }
    pub fn any_vlan() -> Filter { Filter::AnyVlan }
}

pub mod arp {
    use super::Filter;

    pub fn any() -> Filter { Filter::Arp }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    // Build a minimal Ethernet + IPv4 + TCP frame with specified flags.
    // Flags byte uses standard TCP bit order: FIN=0,SYN=1,RST=2,PSH=3,ACK=4,URG=5,ECE=6,CWR=7
    fn make_tcp_frame(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        let mut frame = Vec::with_capacity(60);
        // Ethernet header (14 bytes)
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&src_mac);
        frame.extend_from_slice(&[0x08, 0x00]); // IPv4

        // IPv4 header (20 bytes, no options)
        let ip_total_len: u16 = 40; // 20 IP + 20 TCP
        frame.push(0x45); // version + IHL
        frame.push(0x00); // DSCP + ECN
        frame.extend_from_slice(&ip_total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01]); // ID
        frame.extend_from_slice(&[0x40, 0x00]); // flags (DF) + frag offset
        frame.push(64);   // TTL
        frame.push(6);    // protocol = TCP
        // checksum placeholder
        let cksum_offset = frame.len();
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&src_ip);
        frame.extend_from_slice(&dst_ip);
        // Compute IP header checksum
        let ip_hdr = &frame[14..34];
        let cksum = ip_checksum(ip_hdr);
        frame[cksum_offset] = (cksum >> 8) as u8;
        frame[cksum_offset + 1] = cksum as u8;

        // TCP header (20 bytes, minimum)
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // seq
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
        frame.push(0x50); // data offset = 5 (20 bytes), reserved = 0
        frame.push(flags);
        frame.extend_from_slice(&[0x00, 0x00]); // window
        frame.extend_from_slice(&[0x00, 0x00]); // checksum (not validated)
        frame.extend_from_slice(&[0x00, 0x00]); // urgent

        frame
    }

    fn make_arp_frame() -> Vec<u8> {
        let mut frame = Vec::with_capacity(42);
        frame.extend_from_slice(&[0xff; 6]); // dst = broadcast
        frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src
        frame.extend_from_slice(&[0x08, 0x06]); // ARP
        // ARP payload (28 bytes)
        frame.extend_from_slice(&[0x00, 0x01]); // HTYPE = Ethernet
        frame.extend_from_slice(&[0x08, 0x00]); // PTYPE = IPv4
        frame.push(6); // HLEN
        frame.push(4); // PLEN
        frame.extend_from_slice(&[0x00, 0x01]); // OP = request
        frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // sender MAC
        frame.extend_from_slice(&[10, 0, 0, 1]); // sender IP
        frame.extend_from_slice(&[0x00; 6]); // target MAC
        frame.extend_from_slice(&[10, 0, 0, 2]); // target IP
        frame
    }

    fn ip_checksum(hdr: &[u8]) -> u16 {
        let mut acc: u32 = 0;
        let mut i = 0;
        while i + 1 < hdr.len() {
            acc += u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
            i += 2;
        }
        if i < hdr.len() {
            acc += (hdr[i] as u32) << 8;
        }
        while acc >> 16 != 0 {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        !(acc as u16)
    }

    #[test]
    fn syn_flag_match() {
        let frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80,
            0x02, // SYN
        );
        assert!(tcp::syn().matches(&frame));
        assert!(!tcp::ack().matches(&frame));
        assert!(!tcp::fin().matches(&frame));
    }

    #[test]
    fn syn_ack_flags() {
        let frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80,
            0x12, // SYN + ACK
        );
        assert!(tcp::syn().matches(&frame));
        assert!(tcp::ack().matches(&frame));
        // SYN-only should NOT match a SYN-ACK
        let syn_only = tcp::syn() & !tcp::ack();
        assert!(!syn_only.matches(&frame));
    }

    #[test]
    fn not_filter() {
        let frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80,
            0x02, // SYN only
        );
        let not_syn = !tcp::syn();
        assert!(!not_syn.matches(&frame));

        let not_ack = !tcp::ack();
        assert!(not_ack.matches(&frame));
    }

    #[test]
    fn or_filter() {
        let frame_syn = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80,
            0x02, // SYN
        );
        let frame_fin = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80,
            0x01, // FIN
        );
        let frame_rst = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80,
            0x04, // RST
        );
        let fin_or_rst = tcp::fin() | tcp::rst();
        assert!(!fin_or_rst.matches(&frame_syn));
        assert!(fin_or_rst.matches(&frame_fin));
        assert!(fin_or_rst.matches(&frame_rst));
    }

    #[test]
    fn and_filter() {
        let frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80,
            0x12, // SYN + ACK
        );
        let syn_and_ack = tcp::syn() & tcp::ack();
        assert!(syn_and_ack.matches(&frame));

        let syn_and_fin = tcp::syn() & tcp::fin();
        assert!(!syn_and_fin.matches(&frame));
    }

    #[test]
    fn src_host_filter() {
        let frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80,
            0x02,
        );
        let from_src = ip::src("10.0.0.1".parse().unwrap());
        let from_wrong = ip::src("10.0.0.2".parse().unwrap());
        assert!(from_src.matches(&frame));
        assert!(!from_wrong.matches(&frame));
    }

    #[test]
    fn broadcast_filter() {
        let frame = make_arp_frame();
        assert!(eth::broadcast().matches(&frame));
        assert!(!eth::multicast().matches(&frame));
    }

    #[test]
    fn port_filter() {
        let frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80,
            0x02,
        );
        assert!(tcp::src_port(1234).matches(&frame));
        assert!(tcp::dst_port(80).matches(&frame));
        assert!(tcp::port(80).matches(&frame));
        assert!(tcp::port(1234).matches(&frame));
        assert!(!tcp::port(443).matches(&frame));
    }

    #[test]
    fn arp_filter() {
        let arp_frame = make_arp_frame();
        let tcp_frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x02,
        );
        assert!(arp::any().matches(&arp_frame));
        assert!(!arp::any().matches(&tcp_frame));
    }

    #[test]
    fn true_false_filters() {
        let frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x02,
        );
        assert!(Filter::True.matches(&frame));
        assert!(!Filter::False.matches(&frame));
    }

    #[test]
    fn len_filter() {
        let frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x02,
        );
        let n = frame.len();
        assert!(Filter::Len { op: CmpOp::Eq, n }.matches(&frame));
        assert!(Filter::Len { op: CmpOp::Ge, n }.matches(&frame));
        assert!(!Filter::Len { op: CmpOp::Gt, n }.matches(&frame));
    }

    #[test]
    fn byte_at_filter() {
        let frame = make_arp_frame();
        // dst MAC first byte is 0xff (broadcast)
        assert!(Filter::ByteAt { offset: 0, op: CmpOp::Eq, value: 0xff }.matches(&frame));
        assert!(!Filter::ByteAt { offset: 0, op: CmpOp::Eq, value: 0x00 }.matches(&frame));
    }

    #[test]
    fn byte_at_out_of_bounds_returns_false() {
        let frame = make_arp_frame();
        // offset beyond frame length should not panic and should not match
        assert!(!Filter::ByteAt { offset: 9999, op: CmpOp::Eq, value: 0x00 }.matches(&frame));
    }

    #[test]
    fn ether_src_dst_filter() {
        let frame = make_tcp_frame(
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x02,
        );
        let src = crate::eth::MacAddr::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let dst = crate::eth::MacAddr::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let other = crate::eth::MacAddr::from([0x00; 6]);

        assert!(Filter::EtherSrc(src).matches(&frame));
        assert!(!Filter::EtherSrc(dst).matches(&frame));
        assert!(!Filter::EtherSrc(other).matches(&frame));

        assert!(Filter::EtherDst(dst).matches(&frame));
        assert!(!Filter::EtherDst(src).matches(&frame));
    }

    #[test]
    fn ether_proto_filter() {
        let tcp_frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x02,
        );
        let arp_frame = make_arp_frame();

        assert!(Filter::EtherProto(0x0800).matches(&tcp_frame));  // IPv4
        assert!(!Filter::EtherProto(0x0806).matches(&tcp_frame)); // ARP
        assert!(Filter::EtherProto(0x0806).matches(&arp_frame));
        assert!(!Filter::EtherProto(0x0800).matches(&arp_frame));
    }

    #[test]
    fn dst_host_filter() {
        let frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x02,
        );
        assert!(ip::dst("10.0.0.2".parse().unwrap()).matches(&frame));
        assert!(!ip::dst("10.0.0.1".parse().unwrap()).matches(&frame));
    }

    #[test]
    fn src_net_dst_net_cidr() {
        let frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [192, 168, 1, 5],
            1234, 80, 0x02,
        );
        let net10 = crate::ip::Ipv4Cidr::new("10.0.0.0".parse().unwrap(), 8).unwrap();
        let net192 = crate::ip::Ipv4Cidr::new("192.168.1.0".parse().unwrap(), 24).unwrap();
        let net172 = crate::ip::Ipv4Cidr::new("172.16.0.0".parse().unwrap(), 12).unwrap();

        assert!(Filter::SrcNet(net10).matches(&frame));
        assert!(!Filter::SrcNet(net172).matches(&frame));
        assert!(Filter::DstNet(net192).matches(&frame));
        assert!(!Filter::DstNet(net10).matches(&frame));
    }

    #[test]
    fn ip_proto_and_transport_shortcuts() {
        let tcp_frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x02,
        );
        let arp_frame = make_arp_frame();

        assert!(Filter::IpProto(6).matches(&tcp_frame));   // TCP = 6
        assert!(!Filter::IpProto(17).matches(&tcp_frame)); // UDP = 17
        assert!(Filter::Tcp.matches(&tcp_frame));
        assert!(!Filter::Udp.matches(&tcp_frame));
        assert!(!Filter::Icmp.matches(&tcp_frame));
        // ARP has no IP layer so IpProto and transport shortcuts don't match
        assert!(!Filter::IpProto(6).matches(&arp_frame));
        assert!(!Filter::Tcp.matches(&arp_frame));
    }

    #[test]
    fn ip_len_comparison() {
        // make_tcp_frame: ip_total_len = 40 (20 IP + 20 TCP)
        let frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x02,
        );
        assert!(Filter::IpLen { op: CmpOp::Eq, n: 40 }.matches(&frame));
        assert!(Filter::IpLen { op: CmpOp::Le, n: 40 }.matches(&frame));
        assert!(Filter::IpLen { op: CmpOp::Lt, n: 41 }.matches(&frame));
        assert!(Filter::IpLen { op: CmpOp::Ge, n: 40 }.matches(&frame));
        assert!(Filter::IpLen { op: CmpOp::Gt, n: 39 }.matches(&frame));
        assert!(Filter::IpLen { op: CmpOp::Ne, n: 99 }.matches(&frame));
        assert!(!Filter::IpLen { op: CmpOp::Gt, n: 40 }.matches(&frame));
    }

    #[test]
    fn ip_ttl_comparison() {
        // make_tcp_frame sets TTL = 64
        let frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x02,
        );
        assert!(Filter::IpTtl { op: CmpOp::Eq, n: 64 }.matches(&frame));
        assert!(Filter::IpTtl { op: CmpOp::Gt, n: 63 }.matches(&frame));
        assert!(Filter::IpTtl { op: CmpOp::Lt, n: 65 }.matches(&frame));
        assert!(!Filter::IpTtl { op: CmpOp::Eq, n: 63 }.matches(&frame));
    }

    #[test]
    fn ip_df_mf_fragment_flags() {
        // make_tcp_frame sets DF=1, MF=0, offset=0 at frame bytes 20-21
        let df_frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x02,
        );
        assert!(Filter::IpDf.matches(&df_frame));
        assert!(!Filter::IpMf.matches(&df_frame));
        assert!(!Filter::IpFragment.matches(&df_frame)); // DF-only is not a fragment

        // Build a frame with MF=1 (more fragments bit: byte 20 = 0x20)
        let mut mf_frame = df_frame.clone();
        mf_frame[20] = 0x20; // clear DF, set MF
        mf_frame[21] = 0x00;
        // Recompute IP checksum
        let cksum = ip_checksum(&mf_frame[14..34]);
        mf_frame[24] = (cksum >> 8) as u8;
        mf_frame[25] = cksum as u8;
        assert!(Filter::IpMf.matches(&mf_frame));
        assert!(Filter::IpFragment.matches(&mf_frame));
        assert!(!Filter::IpDf.matches(&mf_frame));

        // Build a frame with non-zero fragment offset (bytes 20-21: 0x00 0x08 = offset 8)
        let mut frag_frame = df_frame.clone();
        frag_frame[20] = 0x00;
        frag_frame[21] = 0x08; // fragment offset = 8 (×8 bytes = 64-byte offset)
        let cksum2 = ip_checksum(&frag_frame[14..34]);
        frag_frame[24] = (cksum2 >> 8) as u8;
        frag_frame[25] = cksum2 as u8;
        assert!(Filter::IpFragment.matches(&frag_frame));
        assert!(!Filter::IpMf.matches(&frag_frame)); // MF not set
    }

    #[test]
    fn port_range_filters() {
        let frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x02,
        );
        // SrcPortRange: 1234 in [1000, 2000]
        assert!(Filter::SrcPortRange(1000, 2000).matches(&frame));
        assert!(!Filter::SrcPortRange(2000, 3000).matches(&frame));
        // DstPortRange: 80 in [80, 443]
        assert!(Filter::DstPortRange(80, 443).matches(&frame));
        assert!(!Filter::DstPortRange(443, 8080).matches(&frame));
        // PortRange: matches either src or dst
        assert!(Filter::PortRange(1000, 2000).matches(&frame)); // src=1234 in range
        assert!(Filter::PortRange(80, 443).matches(&frame));    // dst=80 in range
        assert!(!Filter::PortRange(2000, 3000).matches(&frame)); // neither 1234 nor 80 in range
    }

    #[test]
    fn remaining_tcp_flags() {
        // PSH=0x08, URG=0x20, ECE=0x40, CWR=0x80 (standard TCP flags byte order)
        let psh_frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x08,
        );
        assert!(tcp::psh().matches(&psh_frame));
        assert!(!tcp::syn().matches(&psh_frame));

        let urg_frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x20,
        );
        assert!(tcp::urg().matches(&urg_frame));

        let ece_frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x40,
        );
        assert!(tcp::ece().matches(&ece_frame));

        let cwr_frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x80,
        );
        assert!(tcp::cwr().matches(&cwr_frame));
    }

    #[test]
    fn tcp_flags_bitmask() {
        // SYN=0x02, ACK=0x10 → SYN+ACK = 0x12
        let syn_ack = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x12,
        );
        // tcp[13] & 0x12 == 0x02 → SYN set, ACK clear
        assert!(!Filter::TcpFlags { mask: 0x12, value: 0x02 }.matches(&syn_ack));
        // tcp[13] & 0x12 == 0x12 → both SYN and ACK set
        assert!(Filter::TcpFlags { mask: 0x12, value: 0x12 }.matches(&syn_ack));
        // tcp[13] & 0x04 == 0x00 → RST not set
        assert!(Filter::TcpFlags { mask: 0x04, value: 0x00 }.matches(&syn_ack));
    }

    #[test]
    fn multicast_filter() {
        // Construct an Ethernet frame with a multicast destination MAC.
        // 01:00:5e:00:00:01 is a well-known IPv4 multicast MAC.
        let multicast_dst = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01];
        let frame = make_tcp_frame(
            [0xaa; 6], multicast_dst,
            [10, 0, 0, 1], [224, 0, 0, 1],
            1234, 80, 0x02,
        );
        assert!(eth::multicast().matches(&frame));
        assert!(!eth::broadcast().matches(&frame)); // not broadcast
    }

    #[test]
    fn ip_filter_on_non_ip_frame_returns_false() {
        // ARP frame has no IP layer; all IP-specific filters should return false.
        let arp = make_arp_frame();
        assert!(!Filter::SrcHost("10.0.0.1".parse().unwrap()).matches(&arp));
        assert!(!Filter::DstHost("10.0.0.2".parse().unwrap()).matches(&arp));
        assert!(!Filter::IpProto(6).matches(&arp));
        assert!(!Filter::IpDf.matches(&arp));
        assert!(!Filter::IpFragment.matches(&arp));
        assert!(!Filter::Tcp.matches(&arp));
        assert!(!Filter::SrcPort(80).matches(&arp));
    }

    #[test]
    fn len_less_than_and_not_equal() {
        let frame = make_tcp_frame(
            [0xaa; 6], [0xbb; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 0x02,
        );
        let n = frame.len();
        assert!(Filter::Len { op: CmpOp::Lt, n: n + 1 }.matches(&frame));
        assert!(Filter::Len { op: CmpOp::Le, n }.matches(&frame));
        assert!(Filter::Len { op: CmpOp::Ne, n: n + 1 }.matches(&frame));
        assert!(!Filter::Len { op: CmpOp::Eq, n: n + 1 }.matches(&frame));
    }
}
