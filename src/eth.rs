/// Ethernet II frame encode / decode.
use crate::{Error, Result};

pub const HDR_LEN: usize = 14;

pub type MacAddr = [u8; 6];

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP:  u16 = 0x0806;

#[derive(Debug, Clone, Copy)]
pub struct EthHdr {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16,
}

impl EthHdr {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HDR_LEN {
            return Err(Error::InvalidData);
        }
        Ok(EthHdr {
            dst: buf[0..6].try_into().unwrap(),
            src: buf[6..12].try_into().unwrap(),
            ethertype: u16::from_be_bytes([buf[12], buf[13]]),
        })
    }

    pub fn emit(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < HDR_LEN {
            return Err(Error::InvalidInput);
        }
        buf[0..6].copy_from_slice(&self.dst);
        buf[6..12].copy_from_slice(&self.src);
        buf[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
        Ok(())
    }

    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[HDR_LEN..]
    }
}
