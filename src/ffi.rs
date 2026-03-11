// C FFI surface — all `pub unsafe extern "C"` functions.
//
// Safety contract (applies to every function in this module):
// The caller must ensure all pointer arguments are non-null, properly
// aligned, point to initialized memory of the correct type, and remain
// valid for the duration of the call.  These invariants are documented in
// `include/rawket.h`.  Because the safety requirements are uniform and
// documented in the C header, the per-function `# Safety` doc section is
// suppressed below.
#![allow(clippy::missing_safety_doc)]
use core::net::{Ipv4Addr, SocketAddrV4};
use crate::{
    arp_cache,
    eth::MacAddr,
    ip::Ipv4Cidr,
    network::{Network, NetworkConfig},
    tcp::{State, TcpError, TcpPacket, TcpSocket},
    udp::{UdpPacket, UdpSocket},
    Error,
};
use alloc::{boxed::Box, vec::Vec};
use core::{ffi::CStr, ptr, slice};
use libc::{c_int, c_uint, c_ushort};

// ── Network configuration ─────────────────────────────────────────────────────

/// C-visible mirror of [`NetworkConfig`].
///
/// Obtain a zero-initialised default with [`rawket_network_config_default`],
/// then override individual fields before passing the struct to the network
/// constructor.
#[repr(C)]
pub struct RawketNetworkConfig {
    /// Maximum lifetime of an ARP cache entry, in milliseconds.
    pub arp_cache_max_age_ms:          u64,
    /// Fragment-reassembly timeout, in milliseconds.
    pub ip_frag_timeout_ms:            u64,
    /// Maximum bytes held across all in-flight fragment-reassembly buffers.
    pub ip_frag_mem_limit:             libc::size_t,
    /// Maximum concurrent reassembly entries per source IP.  Default: 4.
    pub ip_frag_per_src_max:           libc::size_t,
    /// Maximum ARP cache entries per interface.  Default: 256.
    pub arp_cache_max_entries:         libc::size_t,
    /// Maximum queued frames per unresolved destination IP.  Default: 4.
    pub arp_queue_max_pending:         libc::size_t,
    /// ICMP Unreachable rate limit (messages/second; 0 = unlimited).
    /// Default: 100.
    pub icmp_rate_limit_per_sec:       u32,
    // ── TCP / BBRv3 ──────────────────────────────────────────────────────────
    /// Maximum Segment Size advertised to peers. Default: 1460.
    pub tcp_mss:                       u16,
    /// Initial congestion window in packets. Default: 10.
    pub tcp_initial_cwnd_pkts:         u32,
    /// Minimum RTO in milliseconds. Default: 200.
    pub tcp_rto_min_ms:                u64,
    /// Maximum RTO in milliseconds. Default: 60000.
    pub tcp_rto_max_ms:                u64,
    /// Max consecutive retransmits before Timeout. Default: 15.
    pub tcp_max_retransmits:           u8,
    /// BBRv3 bandwidth filter window in RTT rounds. Default: 10.
    pub tcp_bbr_bw_filter_rounds:      u8,
    /// PROBE_RTT hold duration in milliseconds. Default: 200.
    pub tcp_bbr_probe_rtt_duration_ms: u64,
    /// How often to enter PROBE_RTT in milliseconds. Default: 5000.
    pub tcp_bbr_probe_rtt_interval_ms: u64,
    /// TCP keep-alive idle time in ms (0 = disabled). Default: 0.
    pub tcp_keepalive_idle_ms:         u64,
    /// Interval between keep-alive probes in ms. Default: 75000.
    pub tcp_keepalive_interval_ms:     u64,
    /// Number of unanswered probes before Timeout. Default: 9.
    pub tcp_keepalive_count:           u8,
    /// Maximum bytes buffered in the TCP send buffer.  Default: 1 MiB.
    pub tcp_send_buf_max:              libc::size_t,
    /// Maximum out-of-order segments buffered per TCP connection.
    /// Segments beyond this limit are dropped; at most 4 SACK blocks are
    /// emitted regardless of this value.  Default: 8.
    pub tcp_rx_ooo_max:                libc::size_t,
    // ── Checksum validation ─────────────────────────────────────────────────
    /// Validate IPv4 header checksum on received frames.  Default: false.
    pub checksum_validate_ip:          bool,
    /// Validate TCP checksum on received segments.  Default: false.
    pub checksum_validate_tcp:         bool,
    /// Validate UDP checksum on received datagrams.  Default: false.
    pub checksum_validate_udp:         bool,
}

/// Return a `RawketNetworkConfig` initialised with the library defaults.
#[no_mangle]
pub extern "C" fn rawket_network_config_default() -> RawketNetworkConfig {
    let c = NetworkConfig::default();
    RawketNetworkConfig {
        arp_cache_max_age_ms:          c.arp_cache_max_age_ms,
        ip_frag_timeout_ms:            c.ip_frag_timeout_ms,
        ip_frag_mem_limit:             c.ip_frag_mem_limit,
        ip_frag_per_src_max:           c.ip_frag_per_src_max,
        arp_cache_max_entries:         c.arp_cache_max_entries,
        arp_queue_max_pending:         c.arp_queue_max_pending,
        icmp_rate_limit_per_sec:       c.icmp_rate_limit_per_sec,
        tcp_mss:                       c.tcp_mss,
        tcp_initial_cwnd_pkts:         c.tcp_initial_cwnd_pkts,
        tcp_rto_min_ms:                c.tcp_rto_min_ms,
        tcp_rto_max_ms:                c.tcp_rto_max_ms,
        tcp_max_retransmits:           c.tcp_max_retransmits,
        tcp_bbr_bw_filter_rounds:      c.tcp_bbr_bw_filter_rounds,
        tcp_bbr_probe_rtt_duration_ms: c.tcp_bbr_probe_rtt_duration_ms,
        tcp_bbr_probe_rtt_interval_ms: c.tcp_bbr_probe_rtt_interval_ms,
        tcp_keepalive_idle_ms:         c.tcp_keepalive_idle_ms,
        tcp_keepalive_interval_ms:     c.tcp_keepalive_interval_ms,
        tcp_keepalive_count:           c.tcp_keepalive_count,
        tcp_send_buf_max:              c.tcp_send_buf_max,
        tcp_rx_ooo_max:                c.tcp_rx_ooo_max,
        checksum_validate_ip:          c.checksum_validate_ip,
        checksum_validate_tcp:         c.checksum_validate_tcp,
        checksum_validate_udp:         c.checksum_validate_udp,
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn set_errno(e: Error) {
    let raw = match e {
        Error::Os(n) => n,
        Error::WouldBlock => libc::EAGAIN,
        Error::NotConnected => libc::ENOTCONN,
        Error::InvalidData | Error::InvalidInput => libc::EINVAL,
    };
    unsafe { *libc::__errno_location() = raw };
}

fn set_errno_raw(n: libc::c_int) {
    unsafe { *libc::__errno_location() = n };
}

fn ip_from_c(ip: c_uint) -> Ipv4Addr {
    Ipv4Addr::from(ip.to_ne_bytes())
}

unsafe fn cstr_bytes<'a>(p: *const libc::c_char) -> Option<&'a [u8]> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { CStr::from_ptr(p) }.to_bytes_with_nul())
}

// No-op callbacks used by the FFI path.
fn udp_noop(_: UdpPacket<'_>) {}
fn tcp_noop(_: TcpPacket<'_>) {}
fn tcp_error_noop(_: TcpError) {}

// ── Network ───────────────────────────────────────────────────────────────────

pub struct RawketNetwork(Network);

impl From<RawketNetworkConfig> for NetworkConfig {
    fn from(c: RawketNetworkConfig) -> Self {
        NetworkConfig {
            arp_cache_max_age_ms:          c.arp_cache_max_age_ms,
            ip_frag_timeout_ms:            c.ip_frag_timeout_ms,
            ip_frag_mem_limit:             c.ip_frag_mem_limit,
            ip_frag_per_src_max:           c.ip_frag_per_src_max,
            arp_cache_max_entries:         c.arp_cache_max_entries,
            arp_queue_max_pending:         c.arp_queue_max_pending,
            icmp_rate_limit_per_sec:       c.icmp_rate_limit_per_sec,
            tcp_mss:                       c.tcp_mss,
            tcp_initial_cwnd_pkts:         c.tcp_initial_cwnd_pkts,
            tcp_rto_min_ms:                c.tcp_rto_min_ms,
            tcp_rto_max_ms:                c.tcp_rto_max_ms,
            tcp_max_retransmits:           c.tcp_max_retransmits,
            tcp_bbr_bw_filter_rounds:      c.tcp_bbr_bw_filter_rounds,
            tcp_bbr_probe_rtt_duration_ms: c.tcp_bbr_probe_rtt_duration_ms,
            tcp_bbr_probe_rtt_interval_ms: c.tcp_bbr_probe_rtt_interval_ms,
            tcp_keepalive_idle_ms:         c.tcp_keepalive_idle_ms,
            tcp_keepalive_interval_ms:     c.tcp_keepalive_interval_ms,
            tcp_keepalive_count:           c.tcp_keepalive_count,
            tcp_send_buf_max:              c.tcp_send_buf_max,
            tcp_rx_ooo_max:                c.tcp_rx_ooo_max,
            checksum_validate_ip:          c.checksum_validate_ip,
            checksum_validate_tcp:         c.checksum_validate_tcp,
            checksum_validate_udp:         c.checksum_validate_udp,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rawket_network_new(
    config: *const RawketNetworkConfig,
) -> *mut RawketNetwork {
    let rust_config = if config.is_null() {
        NetworkConfig::default()
    } else {
        NetworkConfig::from(unsafe { core::ptr::read(config) })
    };
    Box::into_raw(Box::new(RawketNetwork(Network::with_config(rust_config))))
}

#[no_mangle]
pub unsafe extern "C" fn rawket_network_free(net: *mut RawketNetwork) {
    if !net.is_null() {
        unsafe { drop(Box::from_raw(net)) };
    }
}

/// One-step interface creation: open an AfPacketSocket on `ifname`, create an
/// Interface with `mac`, attach it, and return the interface index (iface_idx).
/// Uplink indices are internal and not exposed through the public API.
///
/// `rawket_network_add_intf` must be called before any `rawket_tcp_*` or
/// `rawket_udp_*` constructors that reference the same source IP, because
/// those constructors find the interface by matching `src_ip` against
/// already-attached interfaces.
#[no_mangle]
pub unsafe extern "C" fn rawket_network_add_intf(
    net:    *mut RawketNetwork,
    ifname: *const libc::c_char,
    mac:    *const u8,
) -> c_int {
    if net.is_null() || mac.is_null() {
        set_errno_raw(libc::EINVAL);
        return -1;
    }
    let name_bytes = match unsafe { cstr_bytes(ifname) } {
        Some(b) => b,
        None    => { set_errno_raw(libc::EINVAL); return -1; }
    };
    let mac_arr = match <[u8; 6]>::try_from(unsafe { slice::from_raw_parts(mac, 6) }) {
        Ok(m)  => MacAddr::from(m),
        Err(_) => { set_errno_raw(libc::EINVAL); return -1; }
    };

    let net_inner = unsafe { &mut (*net).0 };
    match net_inner.add_interface().mac(mac_arr).bind_afpacket(name_bytes) {
        Ok(iface_idx) => iface_idx as c_int,
        Err(e) => { set_errno(e); -1 }
    }
}

// ── Interface management ──────────────────────────────────────────────────────

/// Helper: get an immutable reference to the interface at `intf_idx`.
///
/// `intf_idx` is an interface index (as returned by `rawket_network_add_intf`),
/// which indexes directly into `Network::interfaces`.
unsafe fn intf_first(net: *const RawketNetwork, intf_idx: c_int)
    -> Option<&'static crate::interface::Interface>
{
    if net.is_null() || intf_idx < 0 { return None; }
    let net_inner = unsafe { &*net };
    let idx = intf_idx as usize;
    net_inner.0.interfaces().get(idx)
}

/// Copy the 6-byte MAC of the interface at `intf_idx` into `mac_out`.
#[no_mangle]
pub unsafe extern "C" fn rawket_intf_get_mac(
    net:      *const RawketNetwork,
    intf_idx: c_int,
    mac_out:  *mut u8,
) -> c_int {
    if mac_out.is_null() {
        set_errno_raw(libc::EINVAL);
        return -1;
    }
    match unsafe { intf_first(net, intf_idx) } {
        Some(iface) => {
            unsafe { ptr::copy_nonoverlapping(iface.mac().as_bytes().as_ptr(), mac_out, 6) };
            0
        }
        None => { set_errno_raw(libc::ENOENT); -1 }
    }
}

/// Replace the MAC of the interface at `intf_idx`, updating the BPF filter.
#[no_mangle]
pub unsafe extern "C" fn rawket_intf_set_mac(
    net:      *mut RawketNetwork,
    intf_idx: c_int,
    mac:      *const u8,
) -> c_int {
    if net.is_null() || mac.is_null() || intf_idx < 0 {
        set_errno_raw(libc::EINVAL);
        return -1;
    }
    let mac_arr = match <[u8; 6]>::try_from(unsafe { slice::from_raw_parts(mac, 6) }) {
        Ok(m)  => MacAddr::from(m),
        Err(_) => { set_errno_raw(libc::EINVAL); return -1; }
    };
    let net_inner = unsafe { &mut (*net).0 };
    match net_inner.set_iface_mac(intf_idx as usize, mac_arr) {
        Ok(()) => 0,
        Err(e) => { set_errno(e); -1 }
    }
}

/// Assign an IPv4 CIDR address to the interface at `intf_idx`.
///
/// Replaces any previously assigned address.  Also automatically installs a
/// connected (on-link) route for the assigned subnet in the network routing
/// table.
#[no_mangle]
pub unsafe extern "C" fn rawket_intf_assign_ip(
    net:        *mut RawketNetwork,
    intf_idx:   c_int,
    ip:         c_uint,
    prefix_len: u8,
) -> c_int {
    if net.is_null() || intf_idx < 0 {
        set_errno_raw(libc::EINVAL);
        return -1;
    }
    let cidr = match Ipv4Cidr::new(ip_from_c(ip), prefix_len) {
        Ok(c)  => c,
        Err(e) => { set_errno(e); return -1; }
    };
    let net_inner = unsafe { &mut (*net).0 };
    let idx = intf_idx as usize;
    if idx >= net_inner.interfaces().len() {
        set_errno_raw(libc::ENOENT);
        return -1;
    }
    net_inner.interfaces_mut()[idx].assign_ip(cidr);
    // Auto-insert a connected (on-link) route for the assigned subnet.
    let connected = Ipv4Cidr::new(cidr.network(), cidr.prefix_len()).unwrap();
    net_inner.route_add(connected, None);
    0
}

// ── Ethernet tap ─────────────────────────────────────────────────────────────

/// C callback type for raw Ethernet frame delivery.
pub type RawketEthRecvFn =
    unsafe extern "C" fn(frame: *const u8, len: libc::size_t, userdata: *mut libc::c_void);

/// Handle returned by [`rawket_open_eth_cb`].
pub struct RawketEthSocket {
    net:       *mut RawketNetwork,
    /// Index into `Network::interfaces` (for socket removal).
    iface_idx: usize,
    /// TX closure captured via `iface.open_eth_tx()` at open time.
    tx:        crate::TxFn,
    id:        usize,
}

// SAFETY: rawket is single-threaded.
unsafe impl Send for RawketEthSocket {}

/// Open an Ethernet tap on `intf_idx`.
///
/// `cb` is called for every frame received on the interface — before ARP/IP
/// dispatch — allowing the caller to inspect or consume raw frames (e.g.
/// for DHCP).  The tap is non-intercepting: frames are still dispatched to
/// ARP/UDP/TCP as normal.
///
/// `rawket_eth_send` MUST NOT be called from within `cb`.
#[no_mangle]
pub unsafe extern "C" fn rawket_open_eth_cb(
    net:      *mut RawketNetwork,
    intf_idx: c_int,
    cb:       Option<RawketEthRecvFn>,
    userdata: *mut libc::c_void,
) -> *mut RawketEthSocket {
    let Some(callback) = cb else {
        set_errno_raw(libc::EINVAL);
        return ptr::null_mut();
    };
    if net.is_null() || intf_idx < 0 {
        set_errno_raw(libc::EINVAL);
        return ptr::null_mut();
    }
    let net_inner = unsafe { &mut (*net).0 };
    let iface_idx = intf_idx as usize;
    if iface_idx >= net_inner.interfaces().len() {
        set_errno_raw(libc::ENOENT);
        return ptr::null_mut();
    }
    let tx = net_inner.iface_mut(iface_idx).open_eth_tx();
    let ud = userdata;
    let id = net_inner.iface_mut(iface_idx).add_eth_socket(move |frame| {
        unsafe { callback(frame.as_ptr(), frame.len(), ud) };
    });
    Box::into_raw(Box::new(RawketEthSocket { net, iface_idx, tx, id }))
}

/// Deregister the Ethernet tap and free its handle.
#[no_mangle]
pub unsafe extern "C" fn rawket_eth_close(eth: *mut RawketEthSocket) {
    if eth.is_null() { return; }
    let e = unsafe { Box::from_raw(eth) };
    if !e.net.is_null() {
        let net_inner = unsafe { &mut (*e.net).0 };
        if e.iface_idx < net_inner.interfaces().len() {
            net_inner.iface_mut(e.iface_idx).remove_eth_socket(e.id);
        }
    }
}

/// Transmit a raw Ethernet frame via the interface associated with `eth`.
///
/// MUST NOT be called from within the [`RawketEthRecvFn`] callback.
#[no_mangle]
pub unsafe extern "C" fn rawket_eth_send(
    eth: *mut RawketEthSocket,
    buf: *const u8,
    len: libc::size_t,
) -> c_int {
    if eth.is_null() || buf.is_null() {
        set_errno_raw(libc::EINVAL);
        return -1;
    }
    let e = unsafe { &mut *eth };
    let frame = unsafe { slice::from_raw_parts(buf, len) };
    match (e.tx)(frame) {
        Ok(()) => 0,
        Err(err) => { set_errno(err); -1 }
    }
}

// ── UDP ───────────────────────────────────────────────────────────────────────

/// Packet information delivered to a C UDP receive callback.
///
/// The `pdu` pointer is valid only for the duration of the callback invocation.
#[repr(C)]
pub struct RawketUdpPacket {
    pub eth_src:  [u8; 6],
    pub eth_dst:  [u8; 6],
    pub ip_src:   c_uint,
    pub ip_dst:   c_uint,
    pub src_port: c_ushort,
    pub dst_port: c_ushort,
    pub pdu:      *const u8,
    pub pdu_len:  usize,
}

/// C receive callback type for UDP sockets.
pub type RawketUdpRecvFn =
    unsafe extern "C" fn(pkt: *const RawketUdpPacket, userdata: *mut libc::c_void);

struct CUdpEntry {
    src_port: u16,
    callback: RawketUdpRecvFn,
    userdata: *mut libc::c_void,
}

// SAFETY: rawket is single-threaded.
static mut C_UDP_TABLE_PTR: *mut Vec<CUdpEntry> = ptr::null_mut();

fn c_udp_table() -> &'static mut Vec<CUdpEntry> {
    unsafe {
        if C_UDP_TABLE_PTR.is_null() {
            C_UDP_TABLE_PTR = Box::into_raw(Box::new(Vec::new()));
        }
        &mut *C_UDP_TABLE_PTR
    }
}

fn c_udp_dispatch(pkt: UdpPacket<'_>) {
    unsafe {
        if C_UDP_TABLE_PTR.is_null() {
            return;
        }
        for entry in &*C_UDP_TABLE_PTR {
            if entry.src_port == pkt.dst.port() {
                let raw_pkt = RawketUdpPacket {
                    eth_src:  pkt.eth_src.octets(),
                    eth_dst:  pkt.eth_dst.octets(),
                    ip_src:   u32::from_ne_bytes(pkt.src.ip().octets()),
                    ip_dst:   u32::from_ne_bytes(pkt.dst.ip().octets()),
                    src_port: pkt.src.port(),
                    dst_port: pkt.dst.port(),
                    pdu:      pkt.pdu.as_ptr(),
                    pdu_len:  pkt.pdu.len(),
                };
                (entry.callback)(&raw_pkt, entry.userdata);
                return;
            }
        }
    }
}

/// Handle to a UDP socket registered with a network interface.
///
/// Created by [`rawket_udp_open`] or [`rawket_udp_open_cb`].
pub struct RawketUdpSocket {
    src_port:  u16,
    net:       *mut RawketNetwork,
    iface_idx: usize,
}

// SAFETY: rawket is single-threaded.
unsafe impl Send for RawketUdpSocket {}

/// Open a UDP socket, optionally with a C receive callback, and register it
/// with `intf_idx`.
///
/// `on_recv` may be NULL for a send-only socket.  The socket is automatically
/// registered for receive dispatch via [`rawket_network_poll_rx`].
///
/// Returns NULL with errno=ENOENT if no interface with `src_ip` is attached.
#[no_mangle]
pub unsafe extern "C" fn rawket_udp_open(
    net:      *mut RawketNetwork,
    intf_idx: c_int,
    src_ip:   c_uint,
    src_port: c_ushort,
    on_recv:  Option<RawketUdpRecvFn>,
    recv_ud:  *mut libc::c_void,
) -> *mut RawketUdpSocket {
    if net.is_null() || intf_idx < 0 {
        set_errno_raw(libc::EINVAL);
        return ptr::null_mut();
    }
    let ip = ip_from_c(src_ip);
    let idx = intf_idx as usize;

    let sock = {
        let net_ref = unsafe { &(*net).0 };
        if idx >= net_ref.interfaces().len() {
            set_errno_raw(libc::ENOENT);
            return ptr::null_mut();
        }
        let iface = match net_ref.find_iface_for_src_ip(ip) {
            Some((_, i, _)) => i,
            None => { set_errno_raw(libc::ENOENT); return ptr::null_mut(); }
        };
        let recv_fn: for<'a> fn(UdpPacket<'a>) = if on_recv.is_some() {
            c_udp_dispatch
        } else {
            udp_noop
        };
        UdpSocket::new(iface, SocketAddrV4::new(ip, src_port), recv_fn)
    };

    // Register callback in the table before moving the socket.
    if let Some(cb) = on_recv {
        c_udp_table().push(CUdpEntry { src_port, callback: cb, userdata: recv_ud });
    }

    // Transfer ownership to the interface at idx.
    let net_inner = unsafe { &mut (*net).0 };
    if idx >= net_inner.interfaces().len() {
        set_errno_raw(libc::ENOENT);
        return ptr::null_mut();
    }
    net_inner.interfaces_mut()[idx].add_udp_socket(sock);

    Box::into_raw(Box::new(RawketUdpSocket { src_port, net, iface_idx: idx }))
}

/// Deregister the UDP socket from its interface and free the handle.
#[no_mangle]
pub unsafe extern "C" fn rawket_udp_close(sock: *mut RawketUdpSocket) {
    if sock.is_null() { return; }
    let s = unsafe { Box::from_raw(sock) };
    // Remove from the interface.
    if !s.net.is_null() {
        let net_inner = unsafe { &mut (*s.net).0 };
        if s.iface_idx < net_inner.interfaces().len() {
            net_inner.interfaces_mut()[s.iface_idx].remove_udp_socket(s.src_port);
        }
    }
    // Remove from the C callback table.
    unsafe {
        if !C_UDP_TABLE_PTR.is_null() {
            if let Some(pos) = (*C_UDP_TABLE_PTR)
                .iter()
                .rposition(|e| e.src_port == s.src_port)
            {
                (*C_UDP_TABLE_PTR).remove(pos);
            }
        }
    }
}

/// Open a UDP socket with an optional receive callback and register it with
/// the interface that owns `src_ip`.
///
/// `on_recv` may be NULL for a send-only socket.  The socket is automatically
/// registered for receive dispatch via [`rawket_network_poll_rx`].
///
/// Returns NULL with errno=ENOENT if no attached interface has `src_ip`.
#[no_mangle]
pub unsafe extern "C" fn rawket_udp_open_cb(
    net:      *mut RawketNetwork,
    src_ip:   c_uint,
    src_port: c_ushort,
    on_recv:  Option<RawketUdpRecvFn>,
    recv_ud:  *mut libc::c_void,
) -> *mut RawketUdpSocket {
    if net.is_null() {
        set_errno_raw(libc::EINVAL);
        return ptr::null_mut();
    }
    let ip = ip_from_c(src_ip);
    let recv_fn: for<'a> fn(UdpPacket<'a>) = if on_recv.is_some() {
        c_udp_dispatch
    } else {
        udp_noop
    };
    let (sock, iface_idx) = {
        let net_ref = unsafe { &(*net).0 };
        let (iface_idx, iface, _) = match net_ref.find_iface_for_src_ip(ip) {
            Some(t) => t,
            None => { set_errno_raw(libc::ENOENT); return ptr::null_mut(); }
        };
        (UdpSocket::new(iface, SocketAddrV4::new(ip, src_port), recv_fn), iface_idx)
    };
    if let Some(cb) = on_recv {
        c_udp_table().push(CUdpEntry { src_port, callback: cb, userdata: recv_ud });
    }
    let net_inner = unsafe { &mut (*net).0 };
    net_inner.interfaces_mut()[iface_idx].add_udp_socket(sock);
    Box::into_raw(Box::new(RawketUdpSocket { src_port, net, iface_idx }))
}

/// Send a UDP datagram.
///
/// The nexthop is resolved via the network routing table, so this works
/// for both on-link and off-subnet destinations.
/// Returns -1 with errno=EAGAIN if the nexthop MAC is not yet in the ARP cache.
/// Returns -1 with errno=EHOSTUNREACH if no route exists for `dst_ip`.
#[no_mangle]
pub unsafe extern "C" fn rawket_udp_send(
    sock:     *mut RawketUdpSocket,
    dst_ip:   c_uint,
    dst_port: c_ushort,
    buf:      *const u8,
    len:      usize,
) -> c_int {
    if sock.is_null() || buf.is_null() {
        set_errno_raw(libc::EINVAL);
        return -1;
    }
    let s = unsafe { &mut *sock };
    let data = unsafe { slice::from_raw_parts(buf, len) };
    let dst = ip_from_c(dst_ip);

    // Route lookup (immutable borrow, result is Copy).
    let nexthop_ip = {
        let net_ref = unsafe { &(*s.net).0 };
        match net_ref.route_get(dst) {
            Some(rr) => rr.nexthop_ip,
            None => { set_errno_raw(libc::EHOSTUNREACH); return -1; }
        }
    };

    let net_ref = unsafe { &mut (*s.net).0 };
    let dst_addr = SocketAddrV4::new(dst, dst_port);
    let iface_idx = s.iface_idx;
    let src_port = s.src_port;
    if iface_idx < net_ref.interfaces().len() {
        let iface = &mut net_ref.interfaces_mut()[iface_idx];
        for udp in iface.udp_sockets.iter_mut() {
            if udp.src_port() == src_port {
                return match udp.send_to_now(data, dst_addr, nexthop_ip) {
                    Ok(()) => 0,
                    Err(e) => { set_errno(e); -1 }
                };
            }
        }
    }
    set_errno_raw(libc::ENOENT);
    -1
}

// ── TCP callback dispatch ─────────────────────────────────────────────────────

/// C receive callback type for TCP sockets.
///
/// `data` points to the received bytes (valid only for the callback duration).
/// `len` is the byte count.  `userdata` is the value supplied at socket creation.
pub type RawketTcpRecvFn =
    unsafe extern "C" fn(data: *const u8, len: libc::size_t, userdata: *mut libc::c_void);

/// C error callback type for TCP sockets.
///
/// `error` is `TcpError::Reset` (1) or `TcpError::Timeout` (2).
pub type RawketTcpErrorFn = unsafe extern "C" fn(error: TcpError, userdata: *mut libc::c_void);

struct TcpCbEntry {
    src_port:   u16,
    on_recv_c:  Option<RawketTcpRecvFn>,
    recv_ud:    *mut libc::c_void,
    on_error_c: Option<RawketTcpErrorFn>,
    error_ud:   *mut libc::c_void,
}

// SAFETY: rawket is single-threaded.
unsafe impl Send for TcpCbEntry {}

static mut C_TCP_TABLE_PTR: *mut Vec<TcpCbEntry> = ptr::null_mut();

fn c_tcp_table() -> &'static mut Vec<TcpCbEntry> {
    unsafe {
        if C_TCP_TABLE_PTR.is_null() {
            C_TCP_TABLE_PTR = Box::into_raw(Box::new(Vec::new()));
        }
        &mut *C_TCP_TABLE_PTR
    }
}

/// Called from TcpSocket's on_recv fn; dispatches to the C recv callback.
/// Uses pkt.dst_port (= socket's src_port) to find the entry.
fn c_tcp_recv_dispatch(pkt: TcpPacket<'_>) {
    unsafe {
        if C_TCP_TABLE_PTR.is_null() { return; }
        for entry in &*C_TCP_TABLE_PTR {
            if entry.src_port == pkt.dst.port() {
                if let Some(cb) = entry.on_recv_c {
                    cb(pkt.pdu.as_ptr(), pkt.pdu.len(), entry.recv_ud);
                }
                return;
            }
        }
    }
}

/// Fire pending error callbacks for all TCP sockets in `net`.
/// Called from rawket_network_poll_rx after poll_rx_with_timeout returns.
fn fire_tcp_errors(net: &mut Network) {
    unsafe {
        if C_TCP_TABLE_PTR.is_null() { return; }
        for iface in net.interfaces_mut() {
            for tcp in iface.tcp_sockets.iter_mut() {
                if let Some(err) = tcp.last_error.take() {
                    let src_port = tcp.src_port();
                    for entry in &*C_TCP_TABLE_PTR {
                        if entry.src_port == src_port {
                            if let Some(cb) = entry.on_error_c {
                                cb(err, entry.error_ud);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
}

// ── TCP ───────────────────────────────────────────────────────────────────────

/// Lightweight handle to a [`TcpSocket`] owned by an [`Interface`].
pub struct RawketTcpSocket {
    net:      *mut RawketNetwork,
    intf_idx: usize,
    src_port: u16,
}

// SAFETY: rawket is single-threaded; the caller is responsible for not calling
// rawket functions from multiple threads concurrently.
unsafe impl Send for RawketTcpSocket {}


/// Initiate an active TCP connection (sends SYN).
///
/// The interface and nexthop are selected via `route_get(dst_ip)`.
/// Returns NULL with errno=EHOSTUNREACH if no route exists for `dst_ip`.
/// Returns NULL with errno=EAGAIN if the nexthop MAC is not yet cached.
///
/// Received data accumulates in the recv buffer for polling with
/// [`rawket_tcp_recv`].  `on_error` may be NULL.
#[no_mangle]
pub unsafe extern "C" fn rawket_tcp_connect(
    net:            *mut RawketNetwork,
    src_port:       c_ushort,
    dst_ip:         c_uint,
    dst_port:       c_ushort,
    on_recv:        Option<RawketTcpRecvFn>,
    recv_userdata:  *mut libc::c_void,
    on_error:       Option<RawketTcpErrorFn>,
    error_userdata: *mut libc::c_void,
) -> *mut RawketTcpSocket {
    if net.is_null() {
        set_errno_raw(libc::EINVAL);
        return ptr::null_mut();
    }
    let dst = ip_from_c(dst_ip);
    let recv_fn: for<'a> fn(TcpPacket<'a>) = if on_recv.is_some() {
        c_tcp_recv_dispatch
    } else {
        tcp_noop
    };
    let (sock, iface_idx) = {
        let net_ref = unsafe { &(*net).0 };
        let rr = match net_ref.route_get(dst) {
            Some(r) => r,
            None => { set_errno_raw(libc::EHOSTUNREACH); return ptr::null_mut(); }
        };
        let cfg = net_ref.tcp_config();
        let iface = match net_ref.interfaces().get(rr.intf_idx) {
            Some(i) => i,
            None => { set_errno_raw(libc::ENOENT); return ptr::null_mut(); }
        };
        let src_addr = SocketAddrV4::new(rr.src_ip, src_port);
        let dst_addr = SocketAddrV4::new(dst, dst_port);
        match TcpSocket::connect_now(
            iface, src_addr, dst_addr, rr.nexthop_ip,
            recv_fn, tcp_error_noop, cfg,
        ) {
            Ok(s)  => (s, rr.intf_idx),
            Err(e) => { set_errno(e); return ptr::null_mut(); }
        }
    };
    {
        let net_inner = unsafe { &mut (*net).0 };
        match net_inner.interfaces_mut().get_mut(iface_idx) {
            Some(iface) => iface.add_tcp_socket(sock),
            None => { set_errno_raw(libc::ENOENT); return ptr::null_mut(); }
        }
    }
    c_tcp_table().push(TcpCbEntry {
        src_port,
        on_recv_c:  on_recv,
        recv_ud:    recv_userdata,
        on_error_c: on_error,
        error_ud:   error_userdata,
    });
    Box::into_raw(Box::new(RawketTcpSocket { net, intf_idx: iface_idx, src_port }))
}

/// Create a passive (listening) TCP socket.
///
/// The interface is selected by matching `src_ip` against attached interfaces.
/// Returns NULL with errno=ENOENT if no attached interface has `src_ip`.
///
/// `on_recv` may be NULL.  `on_error` may be NULL.
#[no_mangle]
pub unsafe extern "C" fn rawket_tcp_listen(
    net:            *mut RawketNetwork,
    src_ip:         c_uint,
    src_port:       c_ushort,
    on_recv:        Option<RawketTcpRecvFn>,
    recv_ud:        *mut libc::c_void,
    on_error:       Option<RawketTcpErrorFn>,
    error_userdata: *mut libc::c_void,
) -> *mut RawketTcpSocket {
    if net.is_null() {
        set_errno_raw(libc::EINVAL);
        return ptr::null_mut();
    }
    let ip = ip_from_c(src_ip);
    let recv_fn: for<'a> fn(TcpPacket<'a>) = if on_recv.is_some() {
        c_tcp_recv_dispatch
    } else {
        tcp_noop
    };
    let (sock, iface_idx) = {
        let net_ref = unsafe { &(*net).0 };
        let (iface_idx, iface, cfg) = match net_ref.find_iface_for_src_ip(ip) {
            Some(t) => t,
            None => { set_errno_raw(libc::ENOENT); return ptr::null_mut(); }
        };
        match TcpSocket::accept(iface, SocketAddrV4::new(ip, src_port), recv_fn, tcp_error_noop, cfg) {
            Ok(s)  => (s, iface_idx),
            Err(e) => { set_errno(e); return ptr::null_mut(); }
        }
    };
    {
        let net_inner = unsafe { &mut (*net).0 };
        match net_inner.interfaces_mut().get_mut(iface_idx) {
            Some(iface) => iface.add_tcp_socket(sock),
            None => { set_errno_raw(libc::ENOENT); return ptr::null_mut(); }
        }
    }
    // Register callbacks in the table.
    c_tcp_table().push(TcpCbEntry {
        src_port,
        on_recv_c:  on_recv,
        recv_ud,
        on_error_c: on_error,
        error_ud:   error_userdata,
    });
    Box::into_raw(Box::new(RawketTcpSocket { net, intf_idx: iface_idx, src_port }))
}


#[no_mangle]
pub unsafe extern "C" fn rawket_tcp_close(sock: *mut RawketTcpSocket) {
    if sock.is_null() { return; }
    let s = unsafe { Box::from_raw(sock) };
    if !s.net.is_null() {
        let net = unsafe { &mut (*s.net).0 };
        if s.intf_idx < net.interfaces().len() {
            net.interfaces_mut()[s.intf_idx].remove_tcp_socket(s.src_port);
        }
    }
    // Remove from the C callback table.
    unsafe {
        if !C_TCP_TABLE_PTR.is_null() {
            if let Some(pos) = (*C_TCP_TABLE_PTR)
                .iter()
                .rposition(|e| e.src_port == s.src_port)
            {
                (*C_TCP_TABLE_PTR).remove(pos);
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rawket_tcp_state(sock: *const RawketTcpSocket) -> c_int {
    unsafe fn resolve(sock: *const RawketTcpSocket) -> State {
        if sock.is_null() { return State::Closed; }
        let s = unsafe { &*sock };
        if s.net.is_null() { return State::Closed; }
        let net = unsafe { &(*s.net).0 };
        let iface = match net.interfaces().get(s.intf_idx) {
            Some(i) => i,
            None    => return State::Closed,
        };
        iface.tcp_sockets.iter()
            .find(|t| t.src_port() == s.src_port)
            .map_or(State::Closed, |t| t.state)
    }
    (unsafe { resolve(sock) }) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn rawket_tcp_send(
    sock: *mut RawketTcpSocket,
    buf: *const u8,
    len: usize,
) -> c_int {
    if sock.is_null() || buf.is_null() {
        set_errno_raw(libc::EINVAL);
        return -1;
    }
    let s = unsafe { &mut *sock };
    let data = unsafe { slice::from_raw_parts(buf, len) };
    if s.net.is_null() { set_errno_raw(libc::ENOTCONN); return -1; }
    let net = unsafe { &mut (*s.net).0 };
    if s.intf_idx >= net.interfaces().len() { set_errno_raw(libc::ENOENT); return -1; }
    let src_port = s.src_port;
    match net.interfaces_mut()[s.intf_idx].tcp_sockets.iter_mut()
        .find(|t| t.src_port() == src_port)
    {
        None => { set_errno_raw(libc::ENOTCONN); -1 }
        Some(t) => match t.send(data) {
            Ok(()) => 0,
            Err(e) => { set_errno(e); -1 }
        }
    }
}

/// Non-blocking receive.  Returns bytes received (0 = nothing ready), -1 on error.
#[no_mangle]
pub unsafe extern "C" fn rawket_tcp_recv(
    sock: *mut RawketTcpSocket,
    buf: *mut u8,
    len: usize,
) -> c_int {
    if sock.is_null() || buf.is_null() {
        set_errno_raw(libc::EINVAL);
        return -1;
    }
    let s = unsafe { &mut *sock };
    let buf_slice = unsafe { slice::from_raw_parts_mut(buf, len) };
    if s.net.is_null() { return 0; }
    let net = unsafe { &mut (*s.net).0 };
    if s.intf_idx >= net.interfaces().len() { return 0; }
    let src_port = s.src_port;
    match net.interfaces_mut()[s.intf_idx].tcp_sockets.iter_mut()
        .find(|t| t.src_port() == src_port)
    {
        None => 0,
        Some(t) => match t.recv(buf_slice) {
            Some(n) => n as c_int,
            None    => 0,
        }
    }
}

/// Initiate graceful close (sends FIN).
#[no_mangle]
pub unsafe extern "C" fn rawket_tcp_shutdown(sock: *mut RawketTcpSocket) -> c_int {
    if sock.is_null() {
        set_errno_raw(libc::EINVAL);
        return -1;
    }
    let s = unsafe { &mut *sock };
    if s.net.is_null() { return 0; }
    let net = unsafe { &mut (*s.net).0 };
    if s.intf_idx >= net.interfaces().len() { return 0; }
    let src_port = s.src_port;
    match net.interfaces_mut()[s.intf_idx].tcp_sockets.iter_mut()
        .find(|t| t.src_port() == src_port)
    {
        None => 0,
        Some(t) => match t.close() {
            Ok(()) => 0,
            Err(e) => { set_errno(e); -1 }
        }
    }
}

// ── Network poll ──────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn rawket_network_poll_rx(
    net:            *mut RawketNetwork,
    max_timeout_ms: c_int,
) -> c_int {
    if net.is_null() {
        set_errno_raw(libc::EINVAL);
        return -1;
    }
    let net_ref = unsafe { &mut (*net).0 };
    let timeout = if max_timeout_ms < 0 { None } else { Some(max_timeout_ms as u64) };
    match net_ref.poll_rx_with_timeout(timeout) {
        Ok(()) => {}
        Err(e) => { set_errno(e); return -1; }
    }
    // Fire pending error callbacks for all interface TCP sockets.
    fire_tcp_errors(unsafe { &mut (*net).0 });
    0
}

// ── Routing table ─────────────────────────────────────────────────────────────

/// Add (or replace) a route in the network routing table.
///
/// `nexthop` is the gateway address in network byte order; pass `0` for an
/// on-link (directly connected) route.
#[no_mangle]
pub unsafe extern "C" fn rawket_route_add(
    net:        *mut RawketNetwork,
    dst_net:    c_uint,
    prefix_len: u8,
    nexthop:    c_uint,
) -> c_int {
    if net.is_null() {
        set_errno_raw(libc::EINVAL);
        return -1;
    }
    let cidr = match Ipv4Cidr::new(ip_from_c(dst_net), prefix_len) {
        Ok(c)  => c,
        Err(e) => { set_errno(e); return -1; }
    };
    let nh = if nexthop == 0 { None } else { Some(ip_from_c(nexthop)) };
    unsafe { &mut (*net).0 }.route_add(cidr, nh);
    0
}

/// Remove the route matching `dst_net/prefix_len` from the routing table.
///
/// No-op if no matching route exists.
#[no_mangle]
pub unsafe extern "C" fn rawket_route_del(
    net:        *mut RawketNetwork,
    dst_net:    c_uint,
    prefix_len: u8,
) -> c_int {
    if net.is_null() {
        set_errno_raw(libc::EINVAL);
        return -1;
    }
    let cidr = match Ipv4Cidr::new(ip_from_c(dst_net), prefix_len) {
        Ok(c)  => c,
        Err(e) => { set_errno(e); return -1; }
    };
    unsafe { &mut (*net).0 }.route_del(cidr);
    0
}

// ── ARP helper ────────────────────────────────────────────────────────────────

/// Broadcast an ARP Request for `target_ip` out of the interface at `intf_idx`.
///
/// Saves callers from building raw Ethernet frames by hand.  The ARP Reply
/// (if any) is processed by [`rawket_network_poll_rx`] and inserted into the
/// ARP cache automatically.
///
/// Returns 0 on success, -1 on error (errno set).
#[no_mangle]
pub unsafe extern "C" fn rawket_arp_request(
    net:       *mut RawketNetwork,
    intf_idx:  c_int,
    target_ip: c_uint,
) -> c_int {
    if net.is_null() || intf_idx < 0 {
        set_errno_raw(libc::EINVAL);
        return -1;
    }
    let target = ip_from_c(target_ip);
    let net_inner = unsafe { &mut (*net).0 };
    let iface_idx = intf_idx as usize;
    if iface_idx >= net_inner.interfaces().len() {
        set_errno_raw(libc::ENOENT);
        return -1;
    }
    let (src_mac, src_ip) = {
        let iface = &net_inner.interfaces()[iface_idx];
        let mac = iface.mac();
        let ip  = match iface.ip() {
            Some(c) => c.addr(),
            None => { set_errno_raw(libc::EADDRNOTAVAIL); return -1; }
        };
        (mac, ip)
    };
    // Find the uplink for this interface to TX the ARP request.
    let uplink_idx = match net_inner.uplink_for_iface(iface_idx) {
        Some(u) => u,
        None    => { set_errno_raw(libc::ENOENT); return -1; }
    };
    match arp_cache::send_request(src_mac, src_ip, target, |f| net_inner.uplinks_mut()[uplink_idx].tx_send(f)) {
        Ok(()) => 0,
        Err(e) => { set_errno(e); -1 }
    }
}
