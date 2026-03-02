/// ICMP (RFC 792) header encode / decode for echo request/reply.
use crate::{
    ip::{checksum_add, checksum_finish},
    Error, Result,
};

pub const HDR_LEN: usize = 8;

pub const TYPE_ECHO_REQUEST:  u8 = 8;
pub const TYPE_ECHO_REPLY:    u8 = 0;
/// Destination Unreachable.  Code 4 = Fragmentation Needed (RFC 1191 PMTUD).
pub const TYPE_DEST_UNREACH:  u8 = 3;

pub struct IcmpHdr {
    pub typ:      u8,
    pub code:     u8,
    pub checksum: u16,
    pub id:       u16,
    pub seq:      u16,
}

impl IcmpHdr {
    /// Decode the 8-byte ICMP header.  Checksum is not validated.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HDR_LEN {
            return Err(Error::InvalidData);
        }
        Ok(IcmpHdr {
            typ:      buf[0],
            code:     buf[1],
            checksum: u16::from_be_bytes([buf[2], buf[3]]),
            id:       u16::from_be_bytes([buf[4], buf[5]]),
            seq:      u16::from_be_bytes([buf[6], buf[7]]),
        })
    }

    /// Emit the 8-byte header into `buf` and compute the RFC 1071 checksum
    /// over the header and `payload` (no pseudo-header for ICMP).
    pub fn emit(&self, buf: &mut [u8], payload: &[u8]) -> Result<()> {
        if buf.len() < HDR_LEN {
            return Err(Error::InvalidInput);
        }
        buf[0] = self.typ;
        buf[1] = self.code;
        buf[2..4].copy_from_slice(&[0, 0]); // checksum placeholder
        buf[4..6].copy_from_slice(&self.id.to_be_bytes());
        buf[6..8].copy_from_slice(&self.seq.to_be_bytes());

        let acc = checksum_add(0, &buf[..HDR_LEN]);
        let acc = checksum_add(acc, payload);
        let csum = checksum_finish(acc);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());
        Ok(())
    }

    /// Return the ICMP payload slice (everything after the 8-byte header).
    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[HDR_LEN..]
    }
}
