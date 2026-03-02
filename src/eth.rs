/// Ethernet II frame encode / decode.
use core::fmt;
use crate::{Error, Result};

pub const HDR_LEN: usize = 14;

/// A 6-byte IEEE 802 MAC address.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);
    pub const ZERO:      MacAddr = MacAddr([0u8; 6]);

    #[inline] pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        MacAddr([a, b, c, d, e, f])
    }

    #[inline] pub fn octets(self) -> [u8; 6] { self.0 }
    #[inline] pub fn as_bytes(&self) -> &[u8; 6] { &self.0 }

    /// True if the I/G (individual/group) bit is set — i.e. multicast or broadcast.
    #[inline] pub fn is_multicast(&self) -> bool { self.0[0] & 1 != 0 }
    #[inline] pub fn is_broadcast(&self) -> bool { self.0 == [0xff; 6] }
    #[inline] pub fn is_zero(&self)      -> bool { self.0 == [0u8; 6] }
}

impl From<[u8; 6]> for MacAddr {
    fn from(b: [u8; 6]) -> Self { MacAddr(b) }
}

impl From<MacAddr> for [u8; 6] {
    fn from(m: MacAddr) -> Self { m.0 }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, x] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{x:02x}")
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// EtherType field of an Ethernet II frame.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct EtherType(u16);

impl EtherType {
    pub const IPV4: Self = Self(0x0800);
    pub const ARP:  Self = Self(0x0806);
    pub fn value(self) -> u16 { self.0 }
}

#[derive(Debug, Clone, Copy)]
pub struct EthHdr {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: EtherType,
}

impl EthHdr {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HDR_LEN {
            return Err(Error::InvalidData);
        }
        Ok(EthHdr {
            dst: MacAddr::from(<[u8; 6]>::try_from(&buf[0..6]).unwrap()),
            src: MacAddr::from(<[u8; 6]>::try_from(&buf[6..12]).unwrap()),
            ethertype: EtherType(u16::from_be_bytes([buf[12], buf[13]])),
        })
    }

    pub fn emit(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < HDR_LEN {
            return Err(Error::InvalidInput);
        }
        buf[0..6].copy_from_slice(self.dst.as_bytes());
        buf[6..12].copy_from_slice(self.src.as_bytes());
        buf[12..14].copy_from_slice(&self.ethertype.0.to_be_bytes());
        Ok(())
    }

    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[HDR_LEN..]
    }
}
