/// AF_PACKET socket with TPACKET_V2 mmap ring buffers.
///
/// One ring for RX, one for TX.  The kernel and userspace share memory;
/// ownership of each frame is indicated by the `tp_status` field in the
/// per-frame `tpacket2_hdr`.
///
/// A single `AfPacketSocket` can serve multiple L3 [`Interface`]s on the same
/// uplink.  [`attach_mac`] / [`detach_mac`] maintain the BPF filter as a
/// union of all registered MACs; [`poll`] dispatches inbound frames to the
/// matching interface's L3 receive handler.
use crate::{eth::MacAddr, Error, Result};
use alloc::{rc::Rc, vec::Vec};
use core::{cell::RefCell, mem, ptr, slice};
use libc::{self, ETH_P_ALL, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE, SOCK_RAW, SOL_PACKET};

// ── Kernel constants not yet in libc ─────────────────────────────────────────

const PACKET_VERSION: libc::c_int = 10;
const PACKET_RX_RING: libc::c_int = 5;
const PACKET_TX_RING: libc::c_int = 13;
const TPACKET_V2: libc::c_int = 1;

const TP_STATUS_KERNEL: u32 = 0;
const TP_STATUS_USER: u32 = 1;
const TP_STATUS_SEND_REQUEST: u32 = 1;
const TP_STATUS_AVAILABLE: u32 = 0;

/// Ring geometry: 16 frames × 65536 bytes = 1 MiB per ring.
///
/// Each frame must be large enough to hold a GRO/LRO super-segment.
/// Linux GRO can combine up to ~64 KiB of TCP payload into a single virtual
/// frame; with FRAME_SIZE = 2048 those frames were silently truncated, causing
/// wrong ACK numbers and ~17 KiB/s throughput instead of line rate.
/// 65536 bytes leaves ~65450 bytes of payload headroom after headers.
pub const FRAME_SIZE: usize = 65536;
const FRAME_COUNT: usize = 16;
/// Each TPACKET block holds exactly one frame.
const BLOCK_SIZE: usize = FRAME_SIZE;
const BLOCK_COUNT: usize = FRAME_COUNT;

#[repr(C)]
struct TpacketReq {
    tp_block_size: libc::c_uint,
    tp_block_nr: libc::c_uint,
    tp_frame_size: libc::c_uint,
    tp_frame_nr: libc::c_uint,
}

#[repr(C)]
struct Tpacket2Hdr {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_sec: u32,
    tp_nsec: u32,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
    _padding: [u8; 4],
}

// ── EtherLink trait ───────────────────────────────────────────────────────────

/// Abstraction over an Ethernet frame I/O endpoint.
///
/// Implemented by [`AfPacketSocket`] (production AF_PACKET ring) and by
/// `VirtualLink` (in-process wire used by the system-test-validator).
pub(crate) trait EtherLink {
    /// Poll for one received frame. Returns a borrowed slice into an internal
    /// buffer. Caller MUST call [`rx_release`] before the next [`rx_recv`].
    fn rx_recv(&mut self) -> Option<&[u8]>;

    /// Release the buffer returned by [`rx_recv`].
    fn rx_release(&mut self);

    /// Copy `frame` into the transmit path and dispatch it.
    fn tx_send(&mut self, frame: &[u8]) -> Result<()>;

    /// Open (or clone) a standalone TX path and return it as a shareable
    /// closure.
    ///
    /// Called once by [`Uplink::attach`](crate::Uplink::attach) to wire the
    /// TX closure into every [`Interface`](crate::Interface) on this uplink.
    /// `AfPacketSocket` clones the shared `TxRing`; `VirtualLink`
    /// clones its `Rc`-wrapped peer queue.
    fn open_tx(&self) -> Result<crate::TxFn>;

    /// Return an OS file descriptor suitable for use with `poll(2)`.
    ///
    /// Implementations that are not backed by a real file descriptor should
    /// return `-1`; `poll(2)` on Linux ignores entries with negative fds,
    /// so the caller will rely on timer-driven wakeups instead.
    fn fd(&self) -> libc::c_int { -1 }

    /// Register `mac` in the link-layer receive filter.
    ///
    /// The default implementation is a no-op (suitable for virtual links that
    /// do their own frame routing).
    fn attach_mac(&mut self, _mac: &MacAddr) -> Result<()> { Ok(()) }

    /// Deregister `mac` from the link-layer receive filter.
    ///
    /// The default implementation is a no-op.
    fn detach_mac(&mut self, _mac: &MacAddr) -> Result<()> { Ok(()) }
}

// ── RingBuffer ────────────────────────────────────────────────────────────

/// Owns the AF_PACKET file descriptor and the mmap region shared by both rings.
///
/// Cleaned up via `Drop`; shared between [`RxRing`] and [`TxRing`] through `Rc`.
struct RingBuffer {
    fd:         libc::c_int,
    map:        *mut libc::c_void,
    ring_bytes: usize,
}

impl Drop for RingBuffer {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.map, self.ring_bytes * 2);
            libc::close(self.fd);
        }
    }
}

// ── RxRing ────────────────────────────────────────────────────────────────────

pub(crate) struct RxRing {
    shared: Rc<RingBuffer>,
    rx_idx: usize,
}

impl RxRing {
    fn frame_ptr(&self, idx: usize) -> *mut Tpacket2Hdr {
        let offset = (idx % FRAME_COUNT) * FRAME_SIZE;
        unsafe { (self.shared.map as *mut u8).add(offset) as *mut Tpacket2Hdr }
    }

    fn recv(&mut self) -> Option<&[u8]> {
        let hdr = self.frame_ptr(self.rx_idx);
        let status = unsafe { ptr::read_volatile(&(*hdr).tp_status) };
        if status & TP_STATUS_USER == 0 {
            return None;
        }
        let snaplen = unsafe { (*hdr).tp_snaplen as usize };
        let mac_off = unsafe { (*hdr).tp_mac as usize };
        let base = hdr as usize + mac_off;
        Some(unsafe { slice::from_raw_parts(base as *const u8, snaplen) })
    }

    fn release(&mut self) {
        let hdr = self.frame_ptr(self.rx_idx);
        unsafe { ptr::write_volatile(&mut (*hdr).tp_status, TP_STATUS_KERNEL) };
        self.rx_idx = self.rx_idx.wrapping_add(1) % FRAME_COUNT;
    }

    fn fd(&self) -> libc::c_int {
        self.shared.fd
    }
}

// ── TxRing ────────────────────────────────────────────────────────────────────

pub(crate) struct TxRing {
    shared: Rc<RingBuffer>,
    tx_idx: usize,
}

impl TxRing {
    fn frame_ptr(&self, idx: usize) -> *mut Tpacket2Hdr {
        let offset = self.shared.ring_bytes + (idx % FRAME_COUNT) * FRAME_SIZE;
        unsafe { (self.shared.map as *mut u8).add(offset) as *mut Tpacket2Hdr }
    }

    fn send(&mut self, frame: &[u8]) -> Result<()> {
        if frame.len() > FRAME_SIZE - mem::size_of::<Tpacket2Hdr>() {
            return Err(Error::InvalidInput);
        }

        let hdr = self.frame_ptr(self.tx_idx);
        let status = unsafe { ptr::read_volatile(&(*hdr).tp_status) };
        if status != TP_STATUS_AVAILABLE {
            return Err(Error::WouldBlock);
        }

        let mac_off = mem::size_of::<Tpacket2Hdr>();
        unsafe {
            let dst = (hdr as *mut u8).add(mac_off);
            ptr::copy_nonoverlapping(frame.as_ptr(), dst, frame.len());
            (*hdr).tp_len = frame.len() as u32;
            (*hdr).tp_snaplen = frame.len() as u32;
            (*hdr).tp_mac = mac_off as u16;
            (*hdr).tp_net = (mac_off + 14) as u16;
            ptr::write_volatile(&mut (*hdr).tp_status, TP_STATUS_SEND_REQUEST);
        }

        self.tx_idx = self.tx_idx.wrapping_add(1) % FRAME_COUNT;

        let rc = unsafe { libc::sendto(self.shared.fd, ptr::null(), 0, 0, ptr::null(), 0) };
        if rc < 0 {
            let e = Error::last_os();
            if e.raw_os() == Some(libc::ENOBUFS) {
                return Err(Error::WouldBlock);
            }
            return Err(e);
        }
        Ok(())
    }
}

// ── AfPacketSocket ────────────────────────────────────────────────────────────

pub struct AfPacketSocket {
    rx:             RxRing,
    tx:             Rc<RefCell<TxRing>>,
    kernel_ifindex: i32,
    /// MAC addresses included in the current BPF filter.
    macs:           Vec<MacAddr>,
}

// SAFETY: used in single-threaded context only
unsafe impl Send for AfPacketSocket {}

impl AfPacketSocket {
    pub(crate) fn kernel_ifindex(&self) -> i32 {
        self.kernel_ifindex
    }

    pub fn open(ifindex: i32) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                SOCK_RAW,
                (ETH_P_ALL as u16).to_be() as libc::c_int,
            )
        };
        if fd < 0 {
            return Err(Error::last_os());
        }

        let version: libc::c_int = TPACKET_V2;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                SOL_PACKET,
                PACKET_VERSION,
                &version as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            unsafe { libc::close(fd) };
            return Err(Error::last_os());
        }

        let req = TpacketReq {
            tp_block_size: BLOCK_SIZE as libc::c_uint,
            tp_block_nr: BLOCK_COUNT as libc::c_uint,
            tp_frame_size: FRAME_SIZE as libc::c_uint,
            tp_frame_nr: FRAME_COUNT as libc::c_uint,
        };

        for ring_opt in [PACKET_RX_RING, PACKET_TX_RING] {
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_PACKET,
                    ring_opt,
                    &req as *const _ as *const libc::c_void,
                    mem::size_of::<TpacketReq>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                unsafe { libc::close(fd) };
                return Err(Error::last_os());
            }
        }

        let ring_bytes = BLOCK_SIZE * BLOCK_COUNT;
        let map = unsafe {
            libc::mmap(
                ptr::null_mut(),
                ring_bytes * 2,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                fd,
                0,
            )
        };
        if map == MAP_FAILED {
            unsafe { libc::close(fd) };
            return Err(Error::last_os());
        }

        let mut sll: libc::sockaddr_ll = unsafe { mem::MaybeUninit::zeroed().assume_init() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = ifindex;
        let rc = unsafe {
            libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            unsafe {
                libc::munmap(map, ring_bytes * 2);
                libc::close(fd);
            }
            return Err(Error::last_os());
        }

        let shared = Rc::new(RingBuffer { fd, map, ring_bytes });
        let rx = RxRing { shared: Rc::clone(&shared), rx_idx: 0 };
        let tx = Rc::new(RefCell::new(TxRing { shared, tx_idx: 0 }));

        Ok(AfPacketSocket { rx, tx, kernel_ifindex: ifindex, macs: Vec::new() })
    }

    /// Look up the kernel interface index for `ifname` (NUL-terminated C string).
    pub fn lookup_kernel_ifindex(ifname: &[u8]) -> Result<i32> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(Error::last_os());
        }
        let mut ifreq: libc::ifreq = unsafe { mem::MaybeUninit::zeroed().assume_init() };
        let len = ifname.len().min(libc::IFNAMSIZ - 1);
        unsafe {
            ptr::copy_nonoverlapping(
                ifname.as_ptr(),
                ifreq.ifr_name.as_mut_ptr() as *mut u8,
                len,
            );
            let rc = libc::ioctl(fd, libc::SIOCGIFINDEX as _, &ifreq);
            libc::close(fd);
            if rc < 0 {
                return Err(Error::last_os());
            }
            Ok(ifreq.ifr_ifru.ifru_ifindex)
        }
    }

    // ── BPF MAC filter + NIC unicast membership ──────────────────────────────

    /// Call `PACKET_ADD_MEMBERSHIP` or `PACKET_DROP_MEMBERSHIP` with
    /// `mr_type = PACKET_MR_UNICAST` for `mac`.
    fn set_membership(&self, mac: &MacAddr, add: bool) -> Result<()> {
        const PACKET_ADD_MEMBERSHIP:  libc::c_int = 1;
        const PACKET_DROP_MEMBERSHIP: libc::c_int = 2;
        const PACKET_MR_UNICAST:      u16 = 3;

        #[repr(C)]
        struct PacketMreq {
            mr_ifindex: libc::c_int,
            mr_type:    u16,
            mr_alen:    u16,
            mr_address: [u8; 8],
        }

        let mut mr_address = [0u8; 8];
        mr_address[..6].copy_from_slice(mac.as_bytes());

        let mreq = PacketMreq {
            mr_ifindex: self.kernel_ifindex,
            mr_type:    PACKET_MR_UNICAST,
            mr_alen:    6,
            mr_address,
        };
        let opt = if add { PACKET_ADD_MEMBERSHIP } else { PACKET_DROP_MEMBERSHIP };
        let rc = unsafe {
            libc::setsockopt(
                self.rx.shared.fd,
                SOL_PACKET,
                opt,
                &mreq as *const _ as *const libc::c_void,
                mem::size_of::<PacketMreq>() as libc::socklen_t,
            )
        };
        if rc < 0 { Err(Error::last_os()) } else { Ok(()) }
    }

    /// Build and attach a classic BPF program that accepts any frame whose
    /// Ethernet destination matches one of the registered MACs or the
    /// broadcast address `[0xff; 6]`.
    ///
    /// Program layout for N unicast MACs:
    /// - Instructions `6i .. 6i+5` (i = 0..N): check MAC i; on match jump to
    ///   the accept instruction, on miss fall through to MAC i+1.
    /// - Instructions `6N .. 6N+5`: check broadcast `[0xff;6]`.
    /// - Instruction `6N+6`: `ret 0xFFFF` (accept).
    /// - Instruction `6N+7`: `ret 0` (drop).
    fn rebuild_filter(&self) -> Result<()> {
        #[repr(C)]
        struct SockFilter { code: u16, jt: u8, jf: u8, k: u32 }
        #[repr(C)]
        struct SockFprog { len: u16, filter: *const SockFilter }
        const SO_ATTACH_FILTER: libc::c_int = 26;
        const LD_H_ABS: u16 = 0x28;
        const JEQ_K:    u16 = 0x15;
        const RET_K:    u16 = 0x06;

        let n = self.macs.len();
        // 6 instructions per unicast MAC + 6 for broadcast + accept + drop.
        let mut prog: Vec<SockFilter> = Vec::with_capacity(6 * (n + 1) + 2);

        for (i, mac) in self.macs.iter().enumerate() {
            let b = mac.as_bytes();
            let mac01 = (b[0] as u32) << 8 | b[1] as u32;
            let mac23 = (b[2] as u32) << 8 | b[3] as u32;
            let mac45 = (b[4] as u32) << 8 | b[5] as u32;
            // On a full match at instruction 6i+5, jump forward to accept.
            // Accept is at index 6*(n+1), so the skip count from 6i+6 is:
            //   6*(n+1) - (6i+6) = 6*(n-i)
            let jt_accept = (6 * (n - i)) as u8;
            prog.push(SockFilter { code: LD_H_ABS, jt: 0, jf: 0, k: 0 });
            prog.push(SockFilter { code: JEQ_K,    jt: 0, jf: 4, k: mac01 });
            prog.push(SockFilter { code: LD_H_ABS, jt: 0, jf: 0, k: 2 });
            prog.push(SockFilter { code: JEQ_K,    jt: 0, jf: 2, k: mac23 });
            prog.push(SockFilter { code: LD_H_ABS, jt: 0, jf: 0, k: 4 });
            prog.push(SockFilter { code: JEQ_K,    jt: jt_accept, jf: 0, k: mac45 });
        }

        // Broadcast check — jf offsets are constant regardless of N.
        prog.push(SockFilter { code: LD_H_ABS, jt: 0, jf: 0, k: 0 });
        prog.push(SockFilter { code: JEQ_K,    jt: 0, jf: 5, k: 0xFFFF });
        prog.push(SockFilter { code: LD_H_ABS, jt: 0, jf: 0, k: 2 });
        prog.push(SockFilter { code: JEQ_K,    jt: 0, jf: 3, k: 0xFFFF });
        prog.push(SockFilter { code: LD_H_ABS, jt: 0, jf: 0, k: 4 });
        prog.push(SockFilter { code: JEQ_K,    jt: 0, jf: 1, k: 0xFFFF });
        prog.push(SockFilter { code: RET_K,    jt: 0, jf: 0, k: 0xFFFF }); // accept
        prog.push(SockFilter { code: RET_K,    jt: 0, jf: 0, k: 0 });      // drop

        let fprog = SockFprog { len: prog.len() as u16, filter: prog.as_ptr() };
        let rc = unsafe {
            libc::setsockopt(
                self.rx.shared.fd,
                libc::SOL_SOCKET,
                SO_ATTACH_FILTER,
                &fprog as *const _ as *const libc::c_void,
                mem::size_of::<SockFprog>() as libc::socklen_t,
            )
        };
        if rc < 0 { Err(Error::last_os()) } else { Ok(()) }
    }
}

impl EtherLink for AfPacketSocket {
    /// Return the next available received frame, or `None` if the ring is empty.
    ///
    /// The caller **must** call [`rx_release`] after processing the frame.
    fn rx_recv(&mut self) -> Option<&[u8]> {
        self.rx.recv()
    }

    /// Return the current RX frame to the kernel and advance the index.
    fn rx_release(&mut self) {
        self.rx.release()
    }

    /// Copy `frame` into the next TX slot and signal the kernel.
    ///
    /// Returns `Err(WouldBlock)` if the ring is full.
    fn tx_send(&mut self, frame: &[u8]) -> Result<()> {
        self.tx.borrow_mut().send(frame)
    }

    fn open_tx(&self) -> Result<crate::TxFn> {
        let tx = Rc::clone(&self.tx);
        Ok(Rc::new(move |f: &[u8]| tx.borrow_mut().send(f)))
    }

    fn fd(&self) -> libc::c_int {
        self.rx.fd()
    }

    /// Add `mac` to the set of addresses accepted by the kernel BPF filter
    /// and register it with the NIC's hardware receive filter via
    /// `PACKET_ADD_MEMBERSHIP / PACKET_MR_UNICAST`.
    ///
    /// Without the membership call the NIC drops unicast frames for virtual
    /// MACs before they ever reach the socket; the BPF filter alone is not
    /// sufficient.  No-op if `mac` is already registered.
    fn attach_mac(&mut self, mac: &MacAddr) -> Result<()> {
        if !self.macs.contains(mac) {
            self.macs.push(*mac);
            self.set_membership(mac, true)?;
        }
        self.rebuild_filter()
    }

    /// Remove `mac` from the filter and deregister it from the NIC's hardware
    /// receive filter.  No-op if not present.
    fn detach_mac(&mut self, mac: &MacAddr) -> Result<()> {
        if self.macs.contains(mac) {
            self.set_membership(mac, false)?;
            self.macs.retain(|m| m != mac);
        }
        self.rebuild_filter()
    }
}
