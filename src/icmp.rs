/// ICMP (RFC 792) message encode / decode.
use crate::{
    ip::{checksum_add, checksum_finish},
    Error, Result,
};

pub const HDR_LEN: usize = 8;

/// Typed ICMP messages supported by this stack.
pub enum IcmpMessage {
    EchoRequest { id: u16, seq: u16 },
    EchoReply   { id: u16, seq: u16 },
    /// Type 3 — Destination Unreachable.
    /// `next_hop_mtu` is nonzero only for code 4 (Fragmentation Needed, RFC 1191).
    DestUnreach { code: u8, next_hop_mtu: u16 },
}

impl IcmpMessage {
    /// Decode an 8-byte ICMP header.  Checksum is not validated.
    ///
    /// Returns `Err(InvalidData)` for unrecognised type values.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HDR_LEN {
            return Err(Error::InvalidData);
        }
        let typ  = buf[0];
        let code = buf[1];
        let id   = u16::from_be_bytes([buf[4], buf[5]]);
        let seq  = u16::from_be_bytes([buf[6], buf[7]]);
        match typ {
            8 => Ok(IcmpMessage::EchoRequest { id, seq }),
            0 => Ok(IcmpMessage::EchoReply   { id, seq }),
            3 => {
                // bytes 4-5 are unused (zero); bytes 6-7 are next-hop MTU for code 4.
                let next_hop_mtu = u16::from_be_bytes([buf[6], buf[7]]);
                Ok(IcmpMessage::DestUnreach { code, next_hop_mtu })
            }
            _ => Err(Error::InvalidData),
        }
    }

    /// Emit the 8-byte ICMP header into `buf` and compute the RFC 1071
    /// checksum over the header and `payload` (no pseudo-header for ICMP).
    pub fn emit(&self, buf: &mut [u8], payload: &[u8]) -> Result<()> {
        if buf.len() < HDR_LEN {
            return Err(Error::InvalidInput);
        }
        match self {
            IcmpMessage::EchoRequest { id, seq } => {
                buf[0] = 8; buf[1] = 0;
                buf[2..4].fill(0);
                buf[4..6].copy_from_slice(&id.to_be_bytes());
                buf[6..8].copy_from_slice(&seq.to_be_bytes());
            }
            IcmpMessage::EchoReply { id, seq } => {
                buf[0] = 0; buf[1] = 0;
                buf[2..4].fill(0);
                buf[4..6].copy_from_slice(&id.to_be_bytes());
                buf[6..8].copy_from_slice(&seq.to_be_bytes());
            }
            IcmpMessage::DestUnreach { code, next_hop_mtu } => {
                buf[0] = 3; buf[1] = *code;
                buf[2..4].fill(0);
                buf[4..6].copy_from_slice(&[0, 0]); // unused
                buf[6..8].copy_from_slice(&next_hop_mtu.to_be_bytes());
            }
        }

        let acc = checksum_add(0, &buf[..HDR_LEN]);
        let acc = checksum_add(acc, payload);
        let csum = checksum_finish(acc);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());
        Ok(())
    }
}
