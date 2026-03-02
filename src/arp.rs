/// ARP (RFC 826) header encode / decode for Ethernet + IPv4.
use crate::{eth::MacAddr, Error, Result};

pub const HDR_LEN: usize = 28;

pub const OPER_REQUEST: u16 = 1;
pub const OPER_REPLY:   u16 = 2;

pub struct ArpHdr {
    pub oper: u16,
    pub sha:  MacAddr,  // sender hardware address
    pub spa:  [u8; 4],  // sender protocol (IPv4) address
    pub tha:  MacAddr,  // target hardware address
    pub tpa:  [u8; 4],  // target protocol (IPv4) address
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
        let oper = u16::from_be_bytes([buf[6], buf[7]]);
        let sha  = buf[8..14].try_into().unwrap();
        let spa  = buf[14..18].try_into().unwrap();
        let tha  = buf[18..24].try_into().unwrap();
        let tpa  = buf[24..28].try_into().unwrap();
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
        buf[6..8].copy_from_slice(&self.oper.to_be_bytes());
        buf[8..14].copy_from_slice(&self.sha);
        buf[14..18].copy_from_slice(&self.spa);
        buf[18..24].copy_from_slice(&self.tha);
        buf[24..28].copy_from_slice(&self.tpa);
        Ok(())
    }
}
