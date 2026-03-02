/**
 * rawket.h – C interface to the rawket IP stack.
 *
 * Compile:
 *   cargo build --release
 *   cc -I include myapp.c -L target/release -l rawket -o myapp
 *
 * All functions return 0 (or a positive count) on success and -1 on error
 * with errno set, unless documented otherwise.
 *
 * IP addresses are in NETWORK byte order (big-endian).
 * Port numbers are in HOST byte order.
 * MAC addresses are 6-byte arrays (no byte-order concerns).
 */
#ifndef RAWKET_H
#define RAWKET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Compiler attributes ─────────────────────────────────────────────────── */

#ifdef __GNUC__
#  define RAWKET_NODISCARD __attribute__((warn_unused_result))
#else
#  define RAWKET_NODISCARD
#endif

/* ── Network configuration ───────────────────────────────────────────────── */

/**
 * Configuration knobs for the rawket network stack.
 *
 * Obtain a struct pre-filled with library defaults by calling
 * rawket_network_config_default(), then override individual fields as needed.
 */
typedef struct {
    /** Maximum lifetime of an ARP cache entry (ms). Default: 20 000. */
    uint64_t arp_cache_max_age_ms;

    /**
     * Fragment-reassembly timeout (ms).
     *
     * If all fragments of a datagram do not arrive within this window the
     * partial reassembly is silently discarded.  Default: 30 000.
     */
    uint64_t ip_frag_timeout_ms;

    /**
     * Maximum bytes held across all in-flight fragment-reassembly buffers.
     *
     * When this limit is reached, fragments that would start a *new*
     * reassembly are dropped.  Fragments belonging to a datagram that is
     * already being reassembled are still accepted regardless of the limit.
     * Default: 65 536 (64 KiB).
     */
    size_t ip_frag_mem_limit;

    /**
     * Maximum concurrent reassembly entries allowed per source IP.
     *
     * Prevents a single sender from exhausting the global fragment budget.
     * New fragments from a source that already has this many open entries are
     * silently dropped.  Default: 4.
     */
    size_t ip_frag_per_src_max;

    /**
     * Maximum ARP cache entries per interface.
     *
     * When the table is full and a new IP address is seen, the oldest entry
     * (FIFO) is evicted to make room.  Default: 256.
     */
    size_t arp_cache_max_entries;

    /**
     * Maximum outbound frames queued per unresolved destination IP.
     *
     * Frames beyond this limit are silently dropped while the ARP request for
     * that IP is pending.  Default: 4.
     */
    size_t arp_queue_max_pending;

    /**
     * Maximum ICMP Destination Unreachable messages sent per second per
     * interface.  0 disables rate limiting (unlimited).  Default: 100.
     */
    uint32_t icmp_rate_limit_per_sec;

    /* ── TCP / BBRv3 ──────────────────────────────────────────────────────── */

    /** Maximum Segment Size advertised to peers.  Default: 1460. */
    uint16_t tcp_mss;

    /** Initial congestion window in packets.  Default: 10. */
    uint32_t tcp_initial_cwnd_pkts;

    /** Minimum retransmission timeout (ms).  Default: 200. */
    uint64_t tcp_rto_min_ms;

    /** Maximum retransmission timeout (ms).  Default: 60 000. */
    uint64_t tcp_rto_max_ms;

    /** Consecutive retransmit limit before a Timeout error.  Default: 15. */
    uint8_t  tcp_max_retransmits;

    /** BBRv3 bandwidth filter window in RTT rounds.  Default: 10. */
    uint8_t  tcp_bbr_bw_filter_rounds;

    /** PROBE_RTT hold duration (ms).  Default: 200. */
    uint64_t tcp_bbr_probe_rtt_duration_ms;

    /** How often to enter PROBE_RTT (ms).  Default: 5 000. */
    uint64_t tcp_bbr_probe_rtt_interval_ms;

    /* ── TCP Keep-Alive ───────────────────────────────────────────────────── */

    /**
     * Keep-alive idle time (ms) before the first probe is sent.
     * 0 = disabled (default).
     */
    uint64_t tcp_keepalive_idle_ms;

    /** Interval between keep-alive probes (ms).  Default: 75 000. */
    uint64_t tcp_keepalive_interval_ms;

    /** Number of unanswered probes before a Timeout error.  Default: 9. */
    uint8_t  tcp_keepalive_count;

    /**
     * Maximum bytes buffered in a TCP send buffer.
     *
     * rawket_tcp_send() returns -1/EAGAIN when adding data would exceed this
     * limit.  Default: 1 048 576 (1 MiB).
     */
    size_t   tcp_send_buf_max;

    /**
     * Maximum out-of-order segments buffered per TCP connection.
     *
     * Segments beyond this limit are dropped; the sender must retransmit
     * them.  Note: at most 4 SACK blocks are ever emitted regardless of
     * this value.  Default: 8.
     */
    size_t   tcp_rx_ooo_max;
} RawketNetworkConfig;

/**
 * Return a RawketNetworkConfig initialised with library defaults.
 *
 * Example:
 * @code
 *   RawketNetworkConfig cfg = rawket_network_config_default();
 *   cfg.ip_frag_timeout_ms = 10000;
 *   cfg.tcp_mss = 1200;
 * @endcode
 */
RawketNetworkConfig rawket_network_config_default(void);


/* ── Forward declarations ────────────────────────────────────────────────── */

typedef struct RawketEthSocket  RawketEthSocket;
typedef struct RawketNetwork    RawketNetwork;
typedef struct RawketUdpSocket  RawketUdpSocket;
typedef struct RawketTcpSocket  RawketTcpSocket;


/* ── Network runtime ─────────────────────────────────────────────────────── */

/**
 * Create a network runtime.
 *
 * The timer subsystem is managed internally; callers do not need a separate
 * timers handle.
 *
 * @param config  Configuration, or NULL to use library defaults
 * @return        Opaque handle, or NULL on failure (errno set)
 */
RAWKET_NODISCARD RawketNetwork *rawket_network_new(const RawketNetworkConfig *config);

/** Free a network runtime and all uplinks it owns. */
void rawket_network_free(RawketNetwork *net);

/**
 * Drive receive dispatch, the timer system, and TCP polling.
 *
 * Blocks for at most `max_timeout_ms` milliseconds (pass -1 for no cap).
 * TCP retransmit timers and error callbacks are fired automatically here;
 * callers do not need a separate TCP poll loop.
 *
 * @return 0 on success, -1 on error
 */
RAWKET_NODISCARD int rawket_network_poll_rx(RawketNetwork *net, int max_timeout_ms);


/* ── One-step interface creation ─────────────────────────────────────────── */

/**
 * Open a PacketSocket on `ifname`, create a virtual NIC with `mac`, attach
 * it, and return its interface index.
 *
 * The returned index is used with rawket_intf_* functions, rawket_udp_open(),
 * and rawket_arp_request().
 *
 * Must be called before rawket_tcp_* or rawket_udp_* constructors that
 * reference a src_ip on this interface.
 *
 * @param net     Network handle
 * @param ifname  Physical interface name (e.g. "eth0")
 * @param mac     6-byte virtual MAC address
 * @return        Interface index (>= 0) on success, -1 on error
 */
RAWKET_NODISCARD int rawket_network_add_intf(RawketNetwork *net, const char *ifname,
                                              const uint8_t mac[6]);


/* ── Interface management ────────────────────────────────────────────────── */

/**
 * Copy the 6-byte MAC of the interface at `intf_idx` into `mac_out`.
 *
 * @return 0 on success, -1 on error
 */
RAWKET_NODISCARD int rawket_intf_get_mac(const RawketNetwork *net, int intf_idx,
                                         uint8_t mac_out[6]);

/**
 * Replace the MAC of the interface at `intf_idx`, updating the BPF filter.
 *
 * @return 0 on success, -1 on error
 */
RAWKET_NODISCARD int rawket_intf_set_mac(RawketNetwork *net, int intf_idx,
                                         const uint8_t mac[6]);

/**
 * Assign an IPv4 CIDR address to the interface at `intf_idx`.
 *
 * Replaces any previously assigned address.  Automatically installs a
 * connected (on-link) route for the assigned subnet.  Typically called
 * after DHCP to configure the address obtained from the server.
 *
 * @param ip         IPv4 address (network byte order)
 * @param prefix_len Network prefix length (0–32)
 * @return           0 on success, -1 on error
 */
RAWKET_NODISCARD int rawket_intf_assign_ip(RawketNetwork *net, int intf_idx,
                                            uint32_t ip, uint8_t prefix_len);

/**
 * Add (or replace) a route in the network routing table.
 *
 * @param dst_net    Destination network address (network byte order)
 * @param prefix_len Network prefix length (0–32); use 0 with dst_net=0 for
 *                   the default route 0.0.0.0/0
 * @param nexthop    Gateway IPv4 address (network byte order), or 0 for an
 *                   on-link (directly connected) route
 * @return           0 on success, -1 on error
 */
RAWKET_NODISCARD int rawket_route_add(RawketNetwork *net,
                                      uint32_t dst_net, uint8_t prefix_len,
                                      uint32_t nexthop);

/**
 * Remove the route matching dst_net/prefix_len from the routing table.
 *
 * No-op if no matching route exists.
 *
 * @return 0 on success, -1 on error
 */
RAWKET_NODISCARD int rawket_route_del(RawketNetwork *net,
                                      uint32_t dst_net, uint8_t prefix_len);


/* ── ARP helper ──────────────────────────────────────────────────────────── */

/**
 * Broadcast an ARP Request for `target_ip` out of the interface at `intf_idx`.
 *
 * Saves callers from building raw Ethernet frames by hand.  The ARP Reply
 * (if any) is processed automatically by rawket_network_poll_rx() and
 * inserted into the ARP cache, making subsequent rawket_tcp_connect() or
 * rawket_udp_send() calls succeed instead of returning EAGAIN.
 *
 * @param net        Network handle
 * @param intf_idx   Interface index from rawket_network_add_intf()
 * @param target_ip  Target IPv4 address to resolve (network byte order)
 * @return           0 on success, -1 on error
 */
RAWKET_NODISCARD int rawket_arp_request(RawketNetwork *net, int intf_idx, uint32_t target_ip);


/* ── Ethernet tap ────────────────────────────────────────────────────────── */

/**
 * Callback invoked for every Ethernet frame received on the uplink.
 *
 * Called before ARP/IP dispatch (tap, not intercept).
 * `frame` is valid only for the duration of the callback; copy if needed.
 */
typedef void (*rawket_eth_recv_fn)(const uint8_t *frame, size_t len,
                                   void *userdata);

/**
 * Open an Ethernet tap on `intf_idx`.
 *
 * `cb` is called for every frame received on the uplink before ARP/IP
 * dispatch.  Useful for implementing DHCP or other low-level protocols
 * prior to IP address assignment.
 *
 * @param net       Network handle
 * @param intf_idx  Interface index from rawket_network_add_intf()
 * @param cb        Frame callback (must not be NULL)
 * @param userdata  Passed unchanged to each cb invocation
 * @return          Opaque handle, or NULL on failure (errno set)
 */
RAWKET_NODISCARD RawketEthSocket *rawket_open_eth_cb(RawketNetwork *net, int intf_idx,
                                                     rawket_eth_recv_fn cb, void *userdata);

/** Deregister the tap and free its handle. */
void rawket_eth_close(RawketEthSocket *eth);

/**
 * Transmit a raw Ethernet frame via the uplink.
 *
 * MUST NOT be called from within the rawket_eth_recv_fn callback.
 *
 * @return 0 on success, -1 on error
 */
RAWKET_NODISCARD int rawket_eth_send(RawketEthSocket *eth, const uint8_t *buf, size_t len);


/* ── UDP ─────────────────────────────────────────────────────────────────── */

/**
 * Packet information delivered to a C UDP receive callback.
 *
 * IP addresses are in network byte order.  Port numbers are in host byte order.
 * The `pdu` pointer is only valid for the duration of the callback.
 */
typedef struct {
    uint8_t  eth_src[6];
    uint8_t  eth_dst[6];
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t src_port;
    uint16_t dst_port;
    const uint8_t *pdu;
    size_t         pdu_len;
} RawketUdpPacket;

/** C receive callback type for UDP sockets. */
typedef void (*rawket_udp_recv_fn)(const RawketUdpPacket *pkt, void *userdata);

/**
 * Open a UDP socket and register it with `uplink_idx` for receive dispatch.
 *
 * The interface is selected automatically by matching `src_ip` against the
 * IP addresses assigned to interfaces attached to `net`.  Returns NULL with
 * errno=ENOENT if no attached interface has `src_ip` assigned.
 *
 * `on_recv` may be NULL for a send-only socket.  When provided, it is invoked
 * for every datagram received on `src_port` during rawket_network_poll_rx().
 *
 * @param net        Network handle from rawket_network_new()
 * @param uplink_idx Interface index from rawket_network_add_intf()
 * @param src_ip     Source IPv4 address (network byte order)
 * @param src_port   Source UDP port (host byte order)
 * @param on_recv    Optional receive callback (may be NULL)
 * @param recv_ud    Passed unchanged to each on_recv invocation
 * @return           Opaque handle, or NULL on failure (errno set)
 */
RAWKET_NODISCARD RawketUdpSocket *rawket_udp_open(
    RawketNetwork     *net,
    int                uplink_idx,
    uint32_t           src_ip,
    uint16_t           src_port,
    rawket_udp_recv_fn on_recv,
    void              *recv_ud
);

/**
 * Deregister the UDP socket from its uplink and free the handle.
 *
 * Do not use the handle after this call.
 */
void rawket_udp_close(RawketUdpSocket *sock);

/**
 * Create a UDP socket with a receive callback, without registering it.
 *
 * The socket is not yet attached to any uplink; call
 * rawket_network_add_udp_socket() to register it.  After that call the
 * handle is consumed — do not call rawket_udp_close() on it.
 *
 * @param net      Network handle from rawket_network_new()
 * @param src_ip   Source IPv4 address (network byte order)
 * @param src_port Source UDP port (host byte order)
 * @param on_recv  Optional receive callback (may be NULL)
 * @param recv_ud  Passed unchanged to each on_recv invocation
 * @return         Opaque handle, or NULL on failure (errno set)
 */
RAWKET_NODISCARD RawketUdpSocket *rawket_udp_open_cb(
    RawketNetwork     *net,
    uint32_t           src_ip,
    uint16_t           src_port,
    rawket_udp_recv_fn on_recv,
    void              *recv_ud
);

/**
 * Register a UDP socket (from rawket_udp_open_cb()) with an uplink.
 *
 * Transfers ownership of `sock` to the network stack.  The pointer is freed
 * by this call and must not be used afterwards.
 *
 * @param net      Network handle
 * @param intf_idx Interface index from rawket_network_add_intf()
 * @param sock     Handle from rawket_udp_open_cb()
 * @return         0 on success, -1 on error
 */
RAWKET_NODISCARD int rawket_network_add_udp_socket(RawketNetwork   *net,
                                                    int              intf_idx,
                                                    RawketUdpSocket *sock);

/**
 * Send a UDP datagram.
 *
 * The nexthop is resolved via the network routing table, so this works for
 * both on-link and off-subnet destinations.
 * Returns -1 with errno=EHOSTUNREACH if no route exists for `dst_ip`.
 * Returns -1 with errno=EAGAIN if the nexthop MAC is not yet in the ARP cache.
 *
 * @param sock      Handle from rawket_udp_open()
 * @param dst_ip    Destination IPv4 address (network byte order)
 * @param dst_port  Destination UDP port (host byte order)
 * @param buf       Payload bytes
 * @param len       Payload length
 * @return          0 on success, -1 on error
 */
RAWKET_NODISCARD int rawket_udp_send(
    RawketUdpSocket *sock,
    uint32_t         dst_ip,
    uint16_t         dst_port,
    const uint8_t   *buf,
    size_t           len
);

/** Return the underlying file descriptor (for poll/epoll/select). */
int rawket_udp_fd(const RawketUdpSocket *sock);


/* ── TCP ─────────────────────────────────────────────────────────────────── */

/** TCP connection states returned by rawket_tcp_state(). */
typedef enum {
    RAWKET_TCP_CLOSED       = 0,
    RAWKET_TCP_LISTEN       = 1,
    RAWKET_TCP_SYN_SENT     = 2,
    RAWKET_TCP_SYN_RECEIVED = 3,
    RAWKET_TCP_ESTABLISHED  = 4,
    RAWKET_TCP_FIN_WAIT1    = 5,
    RAWKET_TCP_FIN_WAIT2    = 6,
    RAWKET_TCP_CLOSE_WAIT   = 7,
    RAWKET_TCP_CLOSING      = 8,
    RAWKET_TCP_LAST_ACK     = 9,
    RAWKET_TCP_TIME_WAIT    = 10,
} RawketTcpState;

/** Error codes delivered to the rawket_tcp_error_fn callback. */
typedef enum {
    RAWKET_TCP_ERR_RESET   = 1,
    RAWKET_TCP_ERR_TIMEOUT = 2,
} RawketTcpError;

/**
 * TCP receive callback type.
 *
 * Invoked when data arrives on the connection.  `data` points to the received
 * bytes (valid only for the duration of the callback).  `len` is the byte
 * count.  `userdata` is the value supplied at socket creation.
 *
 * When this callback is provided to rawket_tcp_connect() or
 * rawket_tcp_listen(), received data is delivered here immediately during
 * rawket_network_poll_rx().  rawket_tcp_recv() can still be used to drain
 * any data that accumulated in the internal recv buffer.
 */
typedef void (*rawket_tcp_recv_fn)(const uint8_t *data, size_t len,
                                   void *userdata);

/**
 * TCP error callback type.
 *
 * Invoked when the connection is reset by the peer (RAWKET_TCP_ERR_RESET) or
 * the maximum retransmit count is exceeded (RAWKET_TCP_ERR_TIMEOUT).  The
 * socket transitions to CLOSED before the callback fires.
 *
 * @param error     RAWKET_TCP_ERR_RESET or RAWKET_TCP_ERR_TIMEOUT
 * @param userdata  Value supplied at socket creation
 */
typedef void (*rawket_tcp_error_fn)(RawketTcpError error, void *userdata);

/**
 * Initiate an active TCP connection (sends SYN).
 *
 * The source address and nexthop are selected automatically via the routing
 * table.  Returns NULL with errno=EHOSTUNREACH if no route exists for `dst_ip`.
 * Returns NULL with errno=EAGAIN if the nexthop MAC is not yet cached;
 * call rawket_arp_request() and retry after rawket_network_poll_rx().
 *
 * `on_recv` and `on_error` may both be NULL.
 *
 * @param net            Network handle from rawket_network_new()
 * @param src_port       Local TCP port (host byte order)
 * @param dst_ip         Destination IPv4 address (network byte order)
 * @param dst_port       Destination TCP port (host byte order)
 * @param on_recv        Optional receive callback (may be NULL)
 * @param recv_userdata  Passed unchanged to each on_recv invocation
 * @param on_error       Optional error callback (may be NULL)
 * @param error_userdata Passed unchanged to each on_error invocation
 * @return               Opaque handle, or NULL on failure (errno set)
 */
RAWKET_NODISCARD RawketTcpSocket *rawket_tcp_connect(
    RawketNetwork      *net,
    uint16_t            src_port,
    uint32_t            dst_ip,
    uint16_t            dst_port,
    rawket_tcp_recv_fn  on_recv,
    void               *recv_userdata,
    rawket_tcp_error_fn on_error,
    void               *error_userdata
);

/**
 * Create a passive (listening) TCP socket.
 *
 * The interface is selected by matching `src_ip` against attached interfaces.
 * Returns NULL with errno=ENOENT if no attached interface has `src_ip`.
 *
 * `on_recv` may be NULL.  `on_error` may be NULL.
 *
 * @param net            Network handle from rawket_network_new()
 * @param src_ip         Local IPv4 address to bind (network byte order)
 * @param src_port       Local TCP port (host byte order)
 * @param on_recv        Optional receive callback (may be NULL)
 * @param recv_ud        Passed unchanged to each on_recv invocation
 * @param on_error       Optional error callback (may be NULL)
 * @param error_userdata Passed unchanged to each on_error invocation
 * @return               Opaque handle, or NULL on failure (errno set)
 */
RAWKET_NODISCARD RawketTcpSocket *rawket_tcp_listen(
    RawketNetwork      *net,
    uint32_t            src_ip,
    uint16_t            src_port,
    rawket_tcp_recv_fn  on_recv,
    void               *recv_userdata,
    rawket_tcp_error_fn on_error,
    void               *error_userdata
);

/** Free a TCP socket handle (does NOT send FIN; call rawket_tcp_shutdown first). */
void rawket_tcp_close(RawketTcpSocket *sock);

/** Query the current connection state. */
RAWKET_NODISCARD RawketTcpState rawket_tcp_state(const RawketTcpSocket *sock);

/**
 * Buffer data for sending on an established connection.
 *
 * @return 0 on success, -1 on error (errno=ENOTCONN if not Established)
 */
RAWKET_NODISCARD int rawket_tcp_send(RawketTcpSocket *sock, const uint8_t *buf, size_t len);

/**
 * Receive data (non-blocking).
 *
 * @return Bytes received (0 = nothing ready), or -1 on error
 */
RAWKET_NODISCARD int rawket_tcp_recv(RawketTcpSocket *sock, uint8_t *buf, size_t len);

/**
 * Initiate graceful close (sends FIN).
 *
 * @return 0 on success, -1 on error
 */
RAWKET_NODISCARD int rawket_tcp_shutdown(RawketTcpSocket *sock);


#ifdef __cplusplus
}
#endif
#endif /* RAWKET_H */
