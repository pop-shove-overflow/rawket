/// Simple AF_PACKET raw Ethernet socket.
///
/// Unlike [`AfPacketSocket`], this does not use TPACKET_V2 mmap rings; it uses
/// ordinary `sendto(2)` / `recv(2)` syscalls.  Intended for low-frequency,
/// short-lived uses such as a DHCP client where the ring setup overhead is
/// not worthwhile.
use crate::{Error, Result};
use core::mem;

pub struct RawSocket {
    fd:      libc::c_int,
    ifindex: i32,
}

impl RawSocket {
    /// Open an `AF_PACKET SOCK_RAW` socket bound to `ifindex` and register
    /// `mac` for unicast delivery via `PACKET_ADD_MEMBERSHIP`.
    ///
    /// The membership call ensures the NIC passes frames addressed to a
    /// locally-administered (non-real) MAC up to the socket; without it the
    /// hardware receive filter would silently drop them.
    pub fn open(ifindex: i32, mac: &[u8; 6]) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as libc::c_int,
            )
        };
        if fd < 0 {
            return Err(Error::last_os());
        }

        let mut sll: libc::sockaddr_ll =
            unsafe { mem::MaybeUninit::zeroed().assume_init() };
        sll.sll_family   = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex  = ifindex;
        let rc = unsafe {
            libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            unsafe { libc::close(fd) };
            return Err(Error::last_os());
        }

        let sock = RawSocket { fd, ifindex };
        if let Err(e) = sock.set_membership(mac, true) {
            unsafe { libc::close(fd) };
            return Err(e);
        }
        Ok(sock)
    }

    /// Send a raw Ethernet frame (starting from the Ethernet header).
    pub fn send(&self, frame: &[u8]) -> Result<()> {
        let mut sll: libc::sockaddr_ll =
            unsafe { mem::MaybeUninit::zeroed().assume_init() };
        sll.sll_family  = libc::AF_PACKET as u16;
        sll.sll_ifindex = self.ifindex;
        let rc = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &sll as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 { Err(Error::last_os()) } else { Ok(()) }
    }

    /// Receive one raw Ethernet frame, waiting at most `timeout_ms`
    /// milliseconds.
    ///
    /// Returns `Some(n)` with the number of bytes written into `buf` on
    /// success, or `None` if the timeout expired before a frame arrived.
    pub fn recv(&self, buf: &mut [u8], timeout_ms: i32) -> Result<Option<usize>> {
        let mut pfd = libc::pollfd {
            fd:      self.fd,
            events:  libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc < 0 {
            return Err(Error::last_os());
        }
        if rc == 0 {
            return Ok(None); // timeout
        }
        let n = unsafe {
            libc::recv(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            return Err(Error::last_os());
        }
        Ok(Some(n as usize))
    }

    pub fn fd(&self) -> libc::c_int {
        self.fd
    }

    fn set_membership(&self, mac: &[u8; 6], add: bool) -> Result<()> {
        const PACKET_ADD_MEMBERSHIP:  libc::c_int = 1;
        const PACKET_DROP_MEMBERSHIP: libc::c_int = 2;
        const PACKET_MR_UNICAST:      u16          = 3;

        #[repr(C)]
        struct PacketMreq {
            mr_ifindex: libc::c_int,
            mr_type:    u16,
            mr_alen:    u16,
            mr_address: [u8; 8],
        }

        let mut mr_address = [0u8; 8];
        mr_address[..6].copy_from_slice(mac);
        let mreq = PacketMreq {
            mr_ifindex: self.ifindex,
            mr_type:    PACKET_MR_UNICAST,
            mr_alen:    6,
            mr_address,
        };
        let opt = if add { PACKET_ADD_MEMBERSHIP } else { PACKET_DROP_MEMBERSHIP };
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                opt,
                &mreq as *const _ as *const libc::c_void,
                mem::size_of::<PacketMreq>() as libc::socklen_t,
            )
        };
        if rc < 0 { Err(Error::last_os()) } else { Ok(()) }
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// TX-only AF_PACKET socket.
///
/// Lighter than [`RawSocket`]: no `PACKET_ADD_MEMBERSHIP` call, no receive
/// path.  Used by [`TcpSocket`](crate::tcp::TcpSocket) as its sole transmit
/// channel now that it no longer owns a TPACKET_V2 ring.
pub(crate) struct TxSocket {
    fd:      libc::c_int,
    ifindex: i32,
}

impl TxSocket {
    pub(crate) fn open(ifindex: i32) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as libc::c_int,
            )
        };
        if fd < 0 {
            return Err(Error::last_os());
        }
        let mut sll: libc::sockaddr_ll =
            unsafe { core::mem::MaybeUninit::zeroed().assume_init() };
        sll.sll_family   = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex  = ifindex;
        let rc = unsafe {
            libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            unsafe { libc::close(fd) };
            return Err(Error::last_os());
        }
        Ok(TxSocket { fd, ifindex })
    }

    pub(crate) fn send(&self, frame: &[u8]) -> Result<()> {
        let mut sll: libc::sockaddr_ll =
            unsafe { core::mem::MaybeUninit::zeroed().assume_init() };
        sll.sll_family  = libc::AF_PACKET as u16;
        sll.sll_ifindex = self.ifindex;
        let rc = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &sll as *const _ as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 { Err(Error::last_os()) } else { Ok(()) }
    }
}

impl Drop for TxSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}
