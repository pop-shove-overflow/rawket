#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "rawket.h"
#include "dhcp.h"

/* ── DHCP constants ───────────────────────────────────────────────────────── */

#define DHCP_CLIENT_PORT    68
#define DHCP_SERVER_PORT    67

#define DHCPDISCOVER  1
#define DHCPOFFER     2
#define DHCPREQUEST   3
#define DHCPACK       5
#define DHCPNAK       6

#define DHCP_MAGIC  0x63825363u

/* BOOTP/DHCP op codes */
#define DHCP_OP_BOOTREQUEST     1
#define DHCP_OP_BOOTREPLY       2

/* Hardware types and address lengths */
#define DHCP_HTYPE_ETHERNET     1
#define DHCP_HLEN_ETHERNET      6   /* MAC address length */

/* DHCP flags */
#define DHCP_FLAG_BROADCAST     0x8000u

/* DHCP fixed-header field offsets (byte offsets within the DHCP payload) */
#define DHCP_OFF_XID            4
#define DHCP_OFF_FLAGS          10
#define DHCP_OFF_YIADDR         16
#define DHCP_OFF_CHADDR         28
#define DHCP_FIXED_LEN          236  /* size of fixed DHCP fields before magic cookie */

/* DHCP option codes (RFC 2132) */
#define DHCPOPT_PAD             0
#define DHCPOPT_SUBNET_MASK     1
#define DHCPOPT_ROUTER          3
#define DHCPOPT_DNS_SERVER      6
#define DHCPOPT_REQUESTED_IP    50
#define DHCPOPT_LEASE_TIME      51
#define DHCPOPT_MSG_TYPE        53
#define DHCPOPT_SERVER_ID       54
#define DHCPOPT_PARAM_REQUEST   55
#define DHCPOPT_END             255

/* ── Raw frame layout (Ethernet + IPv4 + UDP + DHCP) ─────────────────────── */

/* Layer sizes */
#define ETH_HDR_LEN     14   /* dst(6) + src(6) + ethertype(2) */
#define IPV4_HDR_LEN    20   /* no options */
#define UDP_HDR_LEN     8
#define DHCP_MAGIC_LEN  4

/* Frame-level byte offsets for each protocol layer */
#define OFF_ETH     0
#define OFF_IP      (OFF_ETH  + ETH_HDR_LEN)
#define OFF_UDP     (OFF_IP   + IPV4_HDR_LEN)
#define OFF_DHCP    (OFF_UDP  + UDP_HDR_LEN)
#define OFF_OPTS    (OFF_DHCP + DHCP_FIXED_LEN + DHCP_MAGIC_LEN)

#define MAX_FRAME   600

/* Ethernet header field offsets (from frame start) */
#define ETH_ALEN            6
#define ETH_OFF_SRC         6
#define ETH_OFF_ETHERTYPE   12

/* EtherType values */
#define ETHERTYPE_IPV4      0x0800u

/* IPv4 header field offsets (from start of IP header) */
#define IPV4_VER_IHL        0x45u   /* version=4, IHL=5 (no options) */
#define IP_DEFAULT_TTL      64
#define IPV4_OFF_TOTLEN     2
#define IPV4_OFF_TTL        8
#define IPV4_OFF_PROTO      9
#define IPV4_OFF_CKSUM      10
#define IPV4_OFF_DST        16

/* UDP header field offsets (from start of UDP header) */
#define UDP_OFF_DPORT       2
#define UDP_OFF_LEN         4

/* ── Frame-building helpers ───────────────────────────────────────────────── */

/* Write a big-endian uint16_t at byte offset `off` in buffer `b`. */
static void wr16(uint8_t *b, int off, uint16_t v)
{
    b[off]     = (v >> 8) & 0xff;
    b[off + 1] =  v       & 0xff;
}

/* Write a big-endian uint32_t at byte offset `off` in buffer `b`. */
static void wr32(uint8_t *b, int off, uint32_t v)
{
    b[off]     = (v >> 24) & 0xff;
    b[off + 1] = (v >> 16) & 0xff;
    b[off + 2] = (v >>  8) & 0xff;
    b[off + 3] =  v        & 0xff;
}

/* RFC 1071 one's-complement checksum over buf[0..len). */
static uint16_t ip_cksum(const uint8_t *buf, int len)
{
    uint32_t sum = 0;
    while (len > 1) {
        sum += ((uint32_t)buf[0] << 8) | buf[1];
        buf += 2;
        len -= 2;
    }
    if (len)
        sum += (uint32_t)*buf << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* ── DHCP packet builder ──────────────────────────────────────────────────── */

/*
 * Build a DHCP DISCOVER (msg_type == DHCPDISCOVER) or REQUEST frame into
 * `frame` (MAX_FRAME bytes).  Returns the total Ethernet frame length.
 */
static int build_dhcp(uint8_t *frame, int msg_type,
                      const uint8_t xid[4], const uint8_t mac[6],
                      uint32_t offered_ip, uint32_t server_id)
{
    memset(frame, 0, MAX_FRAME);

    /* ── Ethernet header ────────────────────────────────────────────────── */
    memset(frame + OFF_ETH,          0xff, ETH_ALEN); /* dst: broadcast      */
    memcpy(frame + OFF_ETH + ETH_OFF_SRC, mac, ETH_ALEN); /* src: client MAC */
    wr16(frame, OFF_ETH + ETH_OFF_ETHERTYPE, ETHERTYPE_IPV4);

    /* ── IPv4 header ─────────────────────────────────────────────────────── */
    frame[OFF_IP + IPV4_OFF_TTL]   = IP_DEFAULT_TTL;
    frame[OFF_IP + IPV4_OFF_PROTO] = IPPROTO_UDP;
    frame[OFF_IP]                  = IPV4_VER_IHL;
    wr32(frame, OFF_IP + IPV4_OFF_DST, INADDR_BROADCAST);

    /* ── UDP header ──────────────────────────────────────────────────────── */
    wr16(frame, OFF_UDP,              DHCP_CLIENT_PORT);
    wr16(frame, OFF_UDP + UDP_OFF_DPORT, DHCP_SERVER_PORT);

    /* ── DHCP fixed header ───────────────────────────────────────────────── */
    frame[OFF_DHCP + 0] = DHCP_OP_BOOTREQUEST;
    frame[OFF_DHCP + 1] = DHCP_HTYPE_ETHERNET;
    frame[OFF_DHCP + 2] = DHCP_HLEN_ETHERNET;
    memcpy(frame + OFF_DHCP + DHCP_OFF_XID,    xid, sizeof(uint32_t));
    wr16(frame, OFF_DHCP + DHCP_OFF_FLAGS,      DHCP_FLAG_BROADCAST);
    memcpy(frame + OFF_DHCP + DHCP_OFF_CHADDR,  mac, ETH_ALEN);
    wr32(frame, OFF_DHCP + DHCP_FIXED_LEN,      DHCP_MAGIC); /* magic cookie */

    /* ── DHCP options ────────────────────────────────────────────────────── */
    int o = OFF_OPTS;

    frame[o++] = DHCPOPT_MSG_TYPE; frame[o++] = 1; frame[o++] = (uint8_t)msg_type;

    if (msg_type == DHCPREQUEST) {
        frame[o++] = DHCPOPT_REQUESTED_IP; frame[o++] = sizeof(uint32_t);
        memcpy(frame + o, &offered_ip, sizeof(uint32_t)); o += sizeof(uint32_t);
        frame[o++] = DHCPOPT_SERVER_ID;    frame[o++] = sizeof(uint32_t);
        memcpy(frame + o, &server_id, sizeof(uint32_t)); o += sizeof(uint32_t);
    }

    frame[o++] = DHCPOPT_PARAM_REQUEST; frame[o++] = 4;
    frame[o++] = DHCPOPT_SUBNET_MASK;
    frame[o++] = DHCPOPT_ROUTER;
    frame[o++] = DHCPOPT_DNS_SERVER;
    frame[o++] = DHCPOPT_LEASE_TIME;

    frame[o++] = DHCPOPT_END;

    int frame_len = o;

    wr16(frame, OFF_UDP + UDP_OFF_LEN,   (uint16_t)(frame_len - OFF_UDP));
    wr16(frame, OFF_IP  + IPV4_OFF_TOTLEN, (uint16_t)(frame_len - OFF_IP));
    wr16(frame, OFF_IP  + IPV4_OFF_CKSUM,  ip_cksum(frame + OFF_IP, IPV4_HDR_LEN));

    return frame_len;
}

/* ── DHCP reply parser ────────────────────────────────────────────────────── */

static int parse_dhcp_reply(const uint8_t *frame, int len,
                             const uint8_t xid[4], const uint8_t our_mac[6],
                             uint32_t *out_yiaddr,
                             uint32_t *out_server_id,
                             uint32_t *out_subnet,
                             uint32_t *out_router,
                             uint32_t *out_lease_s,
                             uint32_t *out_dns)
{
    static const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    if (len < OFF_OPTS + 3)
        return 0;

    if (memcmp(frame, bcast, ETH_ALEN) != 0 && memcmp(frame, our_mac, ETH_ALEN) != 0)
        return 0;

    if (((frame[ETH_OFF_ETHERTYPE] << 8) | frame[ETH_OFF_ETHERTYPE + 1]) != ETHERTYPE_IPV4) return 0;
    if (frame[OFF_IP + IPV4_OFF_PROTO] != IPPROTO_UDP)                                        return 0;
    if (((frame[OFF_UDP + UDP_OFF_DPORT] << 8) | frame[OFF_UDP + UDP_OFF_DPORT + 1]) != DHCP_CLIENT_PORT)
        return 0;
    if (frame[OFF_DHCP + 0] != DHCP_OP_BOOTREPLY)                        return 0;
    if (memcmp(frame + OFF_DHCP + DHCP_OFF_XID, xid, sizeof(uint32_t)) != 0) return 0;

    memcpy(out_yiaddr, frame + OFF_DHCP + DHCP_OFF_YIADDR, sizeof(uint32_t));

    uint32_t magic;
    memcpy(&magic, frame + OFF_DHCP + DHCP_FIXED_LEN, sizeof(uint32_t));
    if (ntohl(magic) != DHCP_MAGIC)
        return 0;

    int msg_type = 0;
    int o = OFF_OPTS;
    while (o < len) {
        uint8_t opt = frame[o++];
        if (opt == 255) break;
        if (opt == 0)   continue;
        if (o >= len)   break;
        uint8_t olen = frame[o++];
        if (o + olen > len) break;

        switch (opt) {
        case DHCPOPT_MSG_TYPE:    if (olen >= 1) msg_type = frame[o];                              break;
        case DHCPOPT_SERVER_ID:   if (olen >= (int)sizeof(uint32_t)) memcpy(out_server_id, frame + o, sizeof(uint32_t)); break;
        case DHCPOPT_SUBNET_MASK: if (olen >= (int)sizeof(uint32_t)) memcpy(out_subnet,    frame + o, sizeof(uint32_t)); break;
        case DHCPOPT_ROUTER:      if (olen >= (int)sizeof(uint32_t)) memcpy(out_router,    frame + o, sizeof(uint32_t)); break;
        case DHCPOPT_LEASE_TIME:
            if (olen >= (int)sizeof(uint32_t))
                *out_lease_s = ((uint32_t)frame[o]     << 24)
                             | ((uint32_t)frame[o + 1] << 16)
                             | ((uint32_t)frame[o + 2] <<  8)
                             |  (uint32_t)frame[o + 3];
            break;
        case DHCPOPT_DNS_SERVER:  if (olen >= (int)sizeof(uint32_t)) memcpy(out_dns, frame + o, sizeof(uint32_t)); break;
        }
        o += olen;
    }
    return msg_type;
}

/* ── DHCP eth-tap callback ────────────────────────────────────────────────── */

struct DhcpRxState {
    uint8_t buf[MAX_FRAME];
    int     len;
    int     ready;
};

static void dhcp_eth_cb(const uint8_t *frame, size_t len, void *ud)
{
    struct DhcpRxState *s = ud;
    if ((int)len > (int)sizeof(s->buf)) return;
    memcpy(s->buf, frame, len);
    s->len   = (int)len;
    s->ready = 1;
}

/* ── DHCP support helpers ─────────────────────────────────────────────────── */

/* Monotonic clock in milliseconds. */
static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Convert a network-byte-order subnet mask to a CIDR prefix length. */
static uint8_t mask_to_prefix(uint32_t mask_nbo)
{
    uint32_t mask = ntohl(mask_nbo);
    uint8_t  n    = 0;
    while (n < 32 && (mask & 0x80000000u)) { n++; mask <<= 1; }
    return n;
}

/*
 * Wait for a DHCP reply matching `want_type`.
 *
 * Calls rawket_network_poll_rx() which fires dhcp_eth_cb for every received
 * frame.  Returns the message type on match, DHCPNAK on NAK, 0 on timeout.
 */
static int poll_dhcp(RawketNetwork *net, struct DhcpRxState *state,
                     int want_type, int timeout_ms,
                     const uint8_t xid[4], const uint8_t our_mac[6],
                     uint32_t *yiaddr, uint32_t *server_id,
                     uint32_t *subnet, uint32_t *router, uint32_t *lease_s,
                     uint32_t *dns)
{
    long deadline = now_ms() + timeout_ms;

    for (;;) {
        long remaining = deadline - now_ms();
        if (remaining <= 0)
            return 0;

        state->ready = 0;
        int cap = (remaining > INT_MAX) ? INT_MAX : (int)remaining;
        rawket_network_poll_rx(net, cap);
        if (!state->ready)
            return 0;

        int mtype = parse_dhcp_reply(state->buf, state->len, xid, our_mac,
                                     yiaddr, server_id, subnet, router,
                                     lease_s, dns);
        if (mtype == want_type || mtype == DHCPNAK)
            return mtype;
        /* Not our packet — keep draining. */
    }
}

/* ── DHCP client (inner) ──────────────────────────────────────────────────── */

static int dhcp_run_inner(RawketEthSocket *eth_sock, RawketNetwork *net,
                          const uint8_t mac[6], struct DhcpRxState *rx,
                          DhcpLease *lease)
{
    /* Generate a random 4-byte transaction ID. */
    uint8_t xid[4];
    {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0 || read(fd, xid, 4) != 4) {
            perror("urandom (DHCP xid)");
            if (fd >= 0) close(fd);
            return -1;
        }
        close(fd);
    }

    uint8_t  tx[MAX_FRAME];
    uint32_t offered_ip = 0, server_id = 0;
    uint32_t subnet = 0, router = 0, lease_s = 0, dns_server = 0;

    /* ── Phase 1: DISCOVER → OFFER (up to 3 retries) ────────────────────── */
    int got_offer = 0;
    for (int attempt = 1; attempt <= 3 && !got_offer; attempt++) {
        if (attempt > 1)
            printf("Retrying DHCP DISCOVER (attempt %d/3)...\n", attempt);
        else
            printf("Sending DHCP DISCOVER...\n");
        fflush(stdout);

        int tx_len = build_dhcp(tx, DHCPDISCOVER, xid, mac, 0, 0);
        if (rawket_eth_send(eth_sock, tx, tx_len) < 0) {
            perror("rawket_eth_send DHCP DISCOVER");
            continue;
        }

        uint32_t y = 0, srv = 0, sn = 0, gw = 0, lt = 0, dns = 0;
        int mtype = poll_dhcp(net, rx, DHCPOFFER, 4000, xid, mac,
                              &y, &srv, &sn, &gw, &lt, &dns);
        if (mtype == DHCPOFFER && y != 0) {
            char ip_str[INET_ADDRSTRLEN], srv_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &y,   ip_str,  sizeof(ip_str));
            inet_ntop(AF_INET, &srv, srv_str, sizeof(srv_str));
            printf("Received DHCP OFFER from %s — offered %s\n",
                   srv_str, ip_str);
            fflush(stdout);
            offered_ip = y; server_id = srv;
            subnet = sn;    router    = gw;
            lease_s = lt;   dns_server = dns;
            got_offer = 1;
        } else {
            printf("No DHCP OFFER received (4 s timeout).\n");
            fflush(stdout);
        }
    }
    if (!got_offer) {
        fprintf(stderr, "DHCP: no OFFER received after 3 attempts\n");
        return -1;
    }

    /* ── Phase 2: REQUEST → ACK ──────────────────────────────────────────── */
    {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &offered_ip, ip_str, sizeof(ip_str));
        printf("Sending DHCP REQUEST for %s...\n", ip_str);
        fflush(stdout);
    }

    int tx_len = build_dhcp(tx, DHCPREQUEST, xid, mac, offered_ip, server_id);
    if (rawket_eth_send(eth_sock, tx, tx_len) < 0) {
        perror("rawket_eth_send DHCP REQUEST");
        return -1;
    }

    int result = -1;
    {
        uint32_t y = 0, srv = 0, sn = 0, gw = 0, lt = 0, dns = 0;
        int mtype = poll_dhcp(net, rx, DHCPACK, 4000, xid, mac,
                              &y, &srv, &sn, &gw, &lt, &dns);
        if (mtype == DHCPACK && y != 0) {
            lease->ip         = y;
            lease->prefix     = mask_to_prefix(sn ? sn : subnet);
            lease->router     = gw ? gw : router;
            lease->dns_server = dns ? dns : dns_server;
            lease->lease_s    = lt ? lt : lease_s;
            if (lease->prefix == 0) lease->prefix = 24;
            result = 0;
        } else if (mtype == DHCPNAK) {
            fprintf(stderr, "DHCP: server sent NAK\n");
        } else {
            fprintf(stderr, "DHCP: no ACK received (4 s timeout)\n");
        }
    }

    return result;
}

/* ── DHCP public entry point ──────────────────────────────────────────────── */

int dhcp_run(RawketNetwork *net, int intf_idx,
             const uint8_t mac[6], DhcpLease *lease)
{
    struct DhcpRxState rx = {0};
    RawketEthSocket *eth  = rawket_open_eth_cb(net, intf_idx, dhcp_eth_cb, &rx);
    if (!eth) { perror("rawket_open_eth_cb"); return -1; }

    int result = dhcp_run_inner(eth, net, mac, &rx, lease);

    rawket_eth_close(eth);

    if (result == 0) {
        if (rawket_intf_assign_ip(net, intf_idx, lease->ip, lease->prefix) < 0) {
            perror("rawket_intf_assign_ip");
            return -1;
        }
        if (lease->router != 0) {
            /* Add default route 0.0.0.0/0 via DHCP-supplied gateway. */
            if (rawket_route_add(net, 0, 0, lease->router) < 0) {
                perror("rawket_route_add default route");
                return -1;
            }
        }
    }
    return result;
}
