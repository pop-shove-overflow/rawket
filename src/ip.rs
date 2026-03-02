/// IPv4 header encode / decode + one's-complement checksum helpers.
use core::fmt;
use crate::{Error, Result};

pub const MIN_HDR_LEN: usize = 20;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP:  u8 = 6;
pub const PROTO_UDP:  u8 = 17;

/// More-Fragments flag (bit 13 of `flags_frag`).
pub const FLAG_MF: u16 = 0x2000;
/// Don't-Fragment flag (bit 14 of `flags_frag`).
pub const FLAG_DF: u16 = 0x4000;
/// Mask for the 13-bit fragment-offset field (in 8-byte units).
const FRAG_OFFSET_MASK: u16 = 0x1FFF;

#[derive(Debug, Clone, Copy)]
pub struct Ipv4Hdr {
    pub ihl: u8,
    pub dscp_ecn: u8,
    pub total_len: u16,
    pub id: u16,
    pub flags_frag: u16,
    pub ttl: u8,
    pub proto: u8,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

impl Ipv4Hdr {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < MIN_HDR_LEN {
            return Err(Error::InvalidData);
        }
        if buf[0] >> 4 != 4 {
            return Err(Error::InvalidData);
        }
        let ihl = buf[0] & 0xf;
        // IHL must be at least 5 (20 bytes); smaller values are invalid.
        if ihl < 5 {
            return Err(Error::InvalidData);
        }
        let hdr_len = ihl as usize * 4;
        // Buffer must hold the full header (handles IHL > 5 with options).
        if buf.len() < hdr_len {
            return Err(Error::InvalidData);
        }
        // Verify header checksum: one's-complement sum over all header bytes
        // (including the checksum field) must fold to 0xFFFF, which
        // checksum_finish() maps to 0.
        if checksum(&buf[..hdr_len]) != 0 {
            return Err(Error::InvalidData);
        }
        let total_len = u16::from_be_bytes([buf[2], buf[3]]);
        // total_len covers header + payload; it cannot be less than the header.
        if (total_len as usize) < hdr_len {
            return Err(Error::InvalidData);
        }
        Ok(Ipv4Hdr {
            ihl,
            dscp_ecn: buf[1],
            total_len,
            id: u16::from_be_bytes([buf[4], buf[5]]),
            flags_frag: u16::from_be_bytes([buf[6], buf[7]]),
            ttl: buf[8],
            proto: buf[9],
            src: buf[12..16].try_into().unwrap(),
            dst: buf[16..20].try_into().unwrap(),
        })
    }

    /// Emit a minimal IPv4 header (IHL=5).  Checksum is computed automatically.
    pub fn emit(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < MIN_HDR_LEN {
            return Err(Error::InvalidInput);
        }
        buf[0] = (4 << 4) | self.ihl;
        buf[1] = self.dscp_ecn;
        buf[2..4].copy_from_slice(&self.total_len.to_be_bytes());
        buf[4..6].copy_from_slice(&self.id.to_be_bytes());
        buf[6..8].copy_from_slice(&self.flags_frag.to_be_bytes());
        buf[8] = self.ttl;
        buf[9] = self.proto;
        buf[10..12].copy_from_slice(&[0, 0]);
        buf[12..16].copy_from_slice(&self.src);
        buf[16..20].copy_from_slice(&self.dst);
        let csum = checksum(&buf[..MIN_HDR_LEN]);
        buf[10..12].copy_from_slice(&csum.to_be_bytes());
        Ok(())
    }

    pub fn hdr_len(&self) -> usize {
        self.ihl as usize * 4
    }

    /// Fragment payload offset in bytes (wire field is in 8-byte units).
    pub fn frag_offset_bytes(&self) -> usize {
        ((self.flags_frag & FRAG_OFFSET_MASK) as usize) * 8
    }

    /// `true` if this datagram is a fragment (non-zero offset or MF set).
    pub fn is_fragment(&self) -> bool {
        (self.flags_frag & (FLAG_MF | FRAG_OFFSET_MASK)) != 0
    }

    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let start = self.hdr_len();
        let end = (self.total_len as usize).min(buf.len());
        &buf[start..end]
    }
}

// ── Ipv4Cidr ──────────────────────────────────────────────────────────────────

/// An IPv4 address together with its network prefix (CIDR notation).
///
/// Stores the host address as-is; `network()` and `broadcast()` are derived
/// on demand from `prefix_len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    addr:       [u8; 4],
    prefix_len: u8,
}

impl Ipv4Cidr {
    /// Construct from a host address and a prefix length (0–32).
    ///
    /// Returns `Err(InvalidInput)` if `prefix_len > 32`.
    pub fn new(addr: [u8; 4], prefix_len: u8) -> Result<Self> {
        if prefix_len > 32 {
            return Err(Error::InvalidInput);
        }
        Ok(Ipv4Cidr { addr, prefix_len })
    }

    pub fn addr(&self) -> [u8; 4] {
        self.addr
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Subnet mask derived from the prefix length.
    pub fn mask(&self) -> [u8; 4] {
        if self.prefix_len == 0 {
            [0; 4]
        } else {
            (!0u32 << (32 - self.prefix_len)).to_be_bytes()
        }
    }

    /// Network address (`addr & mask`).
    pub fn network(&self) -> [u8; 4] {
        let a = u32::from_be_bytes(self.addr);
        let m = u32::from_be_bytes(self.mask());
        (a & m).to_be_bytes()
    }

    /// Directed broadcast address (`addr | ~mask`).
    pub fn broadcast(&self) -> [u8; 4] {
        let a = u32::from_be_bytes(self.addr);
        let m = u32::from_be_bytes(self.mask());
        (a | !m).to_be_bytes()
    }

    /// Return `true` if `ip` falls within this network (i.e. shares the same
    /// network address after masking).
    pub fn contains(&self, ip: [u8; 4]) -> bool {
        let m = u32::from_be_bytes(self.mask());
        u32::from_be_bytes(ip) & m == u32::from_be_bytes(self.network())
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.addr();
        write!(f, "{a}.{b}.{c}.{d}/{}", self.prefix_len())
    }
}

// ── Checksum ──────────────────────────────────────────────────────────────────

/// Add bytes to a running checksum accumulator.  Does NOT finalize (invert).
pub fn checksum_add(mut acc: u32, data: &[u8]) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        acc += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        acc += (data[i] as u32) << 8;
    }
    // Fold carries periodically so we never overflow u32.
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc
}

/// Fold remaining carries and invert to produce the final checksum word.
pub fn checksum_finish(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// Compute RFC 1071 internet checksum of `data` in one shot.
pub fn checksum(data: &[u8]) -> u16 {
    checksum_finish(checksum_add(0, data))
}

/// Seed a checksum accumulator with the TCP/UDP pseudo-header.
pub fn pseudo_header_acc(src: &[u8; 4], dst: &[u8; 4], proto: u8, length: u16) -> u32 {
    let acc = checksum_add(0, src);
    let acc = checksum_add(acc, dst);
    let acc = checksum_add(acc, &[0, proto]);
    checksum_add(acc, &length.to_be_bytes())
}
