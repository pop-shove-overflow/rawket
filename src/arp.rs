/// ARP (RFC 826) header encode / decode for Ethernet + IPv4.
use core::net::Ipv4Addr;
use crate::{eth::MacAddr, Error, Result};

pub const HDR_LEN: usize = 28;

/// ARP operation code.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ArpOp(u16);

impl ArpOp {
    pub const REQUEST: Self = Self(1);
    pub const REPLY:   Self = Self(2);
}

pub struct ArpHdr {
    pub oper: ArpOp,
    pub sha:  MacAddr,  // sender hardware address
    pub spa:  Ipv4Addr, // sender protocol (IPv4) address
    pub tha:  MacAddr,  // target hardware address
    pub tpa:  Ipv4Addr, // target protocol (IPv4) address
}

impl ArpHdr {
    /// Parse a 28-byte Ethernet+IPv4 ARP payload.
    ///
    /// Returns `Err(InvalidData)` if the buffer is too short or the fixed
    /// fields (`htype`, `ptype`, `hlen`, `plen`) are not the expected values.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HDR_LEN {
            return Err(Error::InvalidData);
        }
        let htype = u16::from_be_bytes([buf[0], buf[1]]);
        let ptype = u16::from_be_bytes([buf[2], buf[3]]);
        let hlen  = buf[4];
        let plen  = buf[5];
        if htype != 1 || ptype != 0x0800 || hlen != 6 || plen != 4 {
            return Err(Error::InvalidData);
        }
        let oper = ArpOp(u16::from_be_bytes([buf[6], buf[7]]));
        let sha  = MacAddr::from(<[u8; 6]>::try_from(&buf[8..14]).unwrap());
        let spa  = Ipv4Addr::from(<[u8; 4]>::try_from(&buf[14..18]).unwrap());
        let tha  = MacAddr::from(<[u8; 6]>::try_from(&buf[18..24]).unwrap());
        let tpa  = Ipv4Addr::from(<[u8; 4]>::try_from(&buf[24..28]).unwrap());
        Ok(ArpHdr { oper, sha, spa, tha, tpa })
    }

    /// Emit the 28-byte ARP header into `buf`.
    ///
    /// `htype`, `ptype`, `hlen`, and `plen` are always written as the
    /// Ethernet+IPv4 constants (1, 0x0800, 6, 4).
    pub fn emit(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < HDR_LEN {
            return Err(Error::InvalidInput);
        }
        buf[0..2].copy_from_slice(&1u16.to_be_bytes());       // htype = Ethernet
        buf[2..4].copy_from_slice(&0x0800u16.to_be_bytes());  // ptype = IPv4
        buf[4] = 6;                                            // hlen
        buf[5] = 4;                                            // plen
        buf[6..8].copy_from_slice(&self.oper.0.to_be_bytes());
        buf[8..14].copy_from_slice(self.sha.as_bytes());
        buf[14..18].copy_from_slice(&self.spa.octets());
        buf[18..24].copy_from_slice(self.tha.as_bytes());
        buf[24..28].copy_from_slice(&self.tpa.octets());
        Ok(())
    }
}
