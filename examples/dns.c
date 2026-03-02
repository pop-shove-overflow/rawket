/**
 * dns.c — Minimal async DNS-A client built on rawket UDP sockets.
 *
 * Wire format references:
 *   RFC 1035 §4 — Message format and name compression
 *   RFC 1035 §3.2 — Resource record format (TYPE A = 1, CLASS IN = 1)
 */

#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "rawket.h"
#include "dns.h"

/* ── Constants ───────────────────────────────────────────────────────────── */

#define DNS_PORT        53
#define DNS_MAX_MSG     512   /* standard DNS message size limit              */
#define DNS_TYPE_A      1
#define DNS_CLASS_IN    1
#define DNS_FLAG_QR     0x8000u  /* response bit in flags field              */
#define DNS_FLAG_RD     0x0100u  /* recursion desired                        */
#define DNS_RCODE_MASK  0x000fu

/* Maximum label length (RFC 1035 §2.3.4) and name depth guard. */
#define DNS_MAX_LABEL   63
#define DNS_LOOP_GUARD  128

/* DNS message structure sizes (RFC 1035 §4.1) */
#define DNS_HDR_LEN             12  /* fixed header: ID+FLAGS+QDCNT+ANCNT+NSCNT+ARCNT */
#define DNS_QUESTION_FIXED_LEN   4  /* QTYPE(2) + QCLASS(2) after the QNAME */
#define DNS_RR_HDR_LEN          10  /* TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2) */
#define DNS_RR_OFF_RDLEN         8  /* RDLENGTH offset within the RR fixed header */

/* Miscellaneous */
#define DNS_INITIAL_TXN_ID  0x4400u  /* arbitrary starting transaction ID */

/* ── Internal types ──────────────────────────────────────────────────────── */

typedef struct {
    dns_resolve_fn  cb;
    void           *userdata;
    char            name[256];
    uint16_t        id;
    int             active;   /* non-zero while waiting for reply            */
} DnsPending;

struct DnsClient {
    RawketUdpSocket *sock;
    uint32_t         dns_server;  /* network byte order                      */
    uint16_t         next_id;
    DnsPending       pending;
};

/* ── DNS query builder ───────────────────────────────────────────────────── */

/*
 * Encode a hostname as a sequence of DNS labels.
 *
 * "example.com"  →  \x07 e x a m p l e \x03 c o m \x00
 * "example.com." →  same (trailing dot handled gracefully)
 *
 * Returns the new offset on success, -1 on overflow or invalid label.
 */
static int encode_name(uint8_t *buf, int off, int max, const char *name)
{
    const char *p = name;

    while (*p) {
        /* Find end of current label. */
        const char *dot = strchr(p, '.');
        int lablen = dot ? (int)(dot - p) : (int)strlen(p);

        if (lablen == 0) {
            /* Trailing dot — root label follows below. */
            p = dot + 1;
            break;
        }
        if (lablen > DNS_MAX_LABEL || off + 1 + lablen >= max)
            return -1;

        buf[off++] = (uint8_t)lablen;
        memcpy(buf + off, p, (size_t)lablen);
        off += lablen;

        p = dot ? dot + 1 : p + lablen;
    }

    /* Root label. */
    if (off + 1 > max)
        return -1;
    buf[off++] = 0;
    return off;
}

/*
 * Build a standard recursive DNS A-record query.
 *
 * Layout: 12-byte header | QNAME labels | QTYPE(2) | QCLASS(2)
 *
 * Returns the total message length on success, -1 on error.
 */
static int build_query(uint8_t *buf, int max, uint16_t id, const char *name)
{
    if (max < DNS_HDR_LEN)
        return -1;

    memset(buf, 0, DNS_HDR_LEN);

    /* Header (RFC 1035 §4.1.1) */
    buf[0]  = (uint8_t)(id >> 8);           /* ID high    */
    buf[1]  = (uint8_t)(id);                /* ID low     */
    buf[2]  = (uint8_t)(DNS_FLAG_RD >> 8);  /* flags: RD=1 */
    buf[3]  = 0x00;
    buf[4]  = 0x00;  /* QDCOUNT high */
    buf[5]  = 0x01;  /* QDCOUNT low  */
    /* ANCOUNT, NSCOUNT, ARCOUNT: 0 */

    /* Question section */
    int off = encode_name(buf, DNS_HDR_LEN, max, name);
    if (off < 0)
        return -1;

    if (off + DNS_QUESTION_FIXED_LEN > max)
        return -1;

    buf[off++] = 0x00;
    buf[off++] = DNS_TYPE_A;    /* QTYPE  = A  (1) */
    buf[off++] = 0x00;
    buf[off++] = DNS_CLASS_IN;  /* QCLASS = IN (1) */

    return off;
}

/* ── DNS response parser ─────────────────────────────────────────────────── */

/*
 * Advance past a DNS name, handling pointer compression (RFC 1035 §4.1.4).
 *
 * Returns the offset immediately after the name field in the wire format,
 * or -1 on a malformed message.
 */
static int skip_name(const uint8_t *msg, int len, int off)
{
    int hops = 0;

    for (;;) {
        if (off >= len)
            return -1;

        uint8_t b = msg[off];

        if (b == 0)
            return off + 1;   /* root label — name ends here */

        if ((b & 0xc0u) == 0xc0u) {
            /* Two-byte pointer — name continues elsewhere; we only need the
             * position after the pointer itself. */
            return off + 2;
        }

        /* Regular label: skip length byte + label bytes. */
        int lablen = b & 0x3f;
        off += 1 + lablen;

        if (++hops > DNS_LOOP_GUARD)
            return -1;
    }
}

/*
 * Parse an answer section of a DNS response and return the first A-record
 * IPv4 address found, or 0 if none.
 *
 * @param msg       Raw DNS message bytes
 * @param len       Total message length
 * @param query_id  Expected transaction ID; the message is silently ignored
 *                  if IDs do not match.
 */
static uint32_t parse_response(const uint8_t *msg, int len, uint16_t query_id)
{
    if (len < DNS_HDR_LEN)
        return 0;

    /* Transaction ID */
    uint16_t id = ((uint16_t)msg[0] << 8) | msg[1];
    if (id != query_id)
        return 0;

    /* Flags — must be a response with RCODE == NOERROR. */
    uint16_t flags = ((uint16_t)msg[2] << 8) | msg[3];
    if (!(flags & DNS_FLAG_QR))
        return 0;
    if ((flags & DNS_RCODE_MASK) != 0)
        return 0;

    uint16_t qdcnt = ((uint16_t)msg[4]  << 8) | msg[5];
    uint16_t ancnt = ((uint16_t)msg[6]  << 8) | msg[7];

    int off = DNS_HDR_LEN;

    /* Skip question section. */
    for (int i = 0; i < qdcnt; i++) {
        off = skip_name(msg, len, off);
        if (off < 0)
            return 0;
        off += DNS_QUESTION_FIXED_LEN;   /* QTYPE + QCLASS */
    }

    /* Walk answer section — return the first A record. */
    for (int i = 0; i < ancnt; i++) {
        off = skip_name(msg, len, off);
        if (off < 0 || off + DNS_RR_HDR_LEN > len)
            return 0;

        uint16_t rtype  = ((uint16_t)msg[off]     << 8) | msg[off + 1];
        uint16_t rclass = ((uint16_t)msg[off + 2] << 8) | msg[off + 3];
        /* TTL occupies msg[off+4..off+7] — unused. */
        uint16_t rdlen  = ((uint16_t)msg[off + DNS_RR_OFF_RDLEN]     << 8)
                        |             msg[off + DNS_RR_OFF_RDLEN + 1];
        off += DNS_RR_HDR_LEN;

        if (rtype == DNS_TYPE_A && rclass == DNS_CLASS_IN && rdlen == sizeof(uint32_t)) {
            if (off + (int)sizeof(uint32_t) > len)
                return 0;
            uint32_t ip;
            memcpy(&ip, msg + off, sizeof(uint32_t));
            return ip;   /* network byte order */
        }

        off += rdlen;
    }

    return 0;
}

/* ── rawket UDP receive callback ─────────────────────────────────────────── */

static void dns_on_recv(const RawketUdpPacket *pkt, void *userdata)
{
    DnsClient *c = (DnsClient *)userdata;

    if (!c->pending.active)
        return;

    /* Accept replies only from the configured DNS server on port 53. */
    if (pkt->ip_src != c->dns_server || pkt->src_port != DNS_PORT)
        return;

    uint32_t ip = parse_response(pkt->pdu, (int)pkt->pdu_len, c->pending.id);
    if (ip == 0) {
        /* Zero return means wrong ID, NXDOMAIN/SERVFAIL, or no A record.
         * Check the transaction ID directly to skip replies not destined for us. */
        uint16_t id = (pkt->pdu_len >= 2)
            ? (uint16_t)(((uint16_t)pkt->pdu[0] << 8) | pkt->pdu[1])
            : 0;
        if (id != c->pending.id)
            return;   /* not our transaction */
    }

    /* Snapshot callback info before clearing state so the callback may
     * immediately call dns_resolve() for a follow-up query. */
    dns_resolve_fn cb       = c->pending.cb;
    void          *ud       = c->pending.userdata;
    char           name[256];
    memcpy(name, c->pending.name, sizeof(name));

    c->pending.active = 0;

    cb(name, ip, ud);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

DnsClient *dns_open(RawketNetwork *net, int uplink,
                    uint32_t src_ip, uint16_t src_port,
                    uint32_t dns_server)
{
    DnsClient *c = (DnsClient *)malloc(sizeof(*c));
    if (!c)
        return NULL;

    memset(c, 0, sizeof(*c));
    c->dns_server = dns_server;
    c->next_id    = DNS_INITIAL_TXN_ID;

    c->sock = rawket_udp_open(net, uplink, src_ip, src_port,
                               dns_on_recv, c);
    if (!c->sock) {
        free(c);
        return NULL;
    }

    return c;
}

int dns_resolve(DnsClient *client, const char *name,
                dns_resolve_fn callback, void *userdata)
{
    if (!client || !name || !callback) {
        errno = EINVAL;
        return -1;
    }
    if (client->pending.active) {
        errno = EBUSY;
        return -1;
    }

    uint16_t id = client->next_id++;

    uint8_t buf[DNS_MAX_MSG];
    int qlen = build_query(buf, (int)sizeof(buf), id, name);
    if (qlen < 0) {
        errno = EINVAL;
        return -1;
    }

    if (rawket_udp_send(client->sock,
                        client->dns_server, DNS_PORT,
                        buf, (size_t)qlen) < 0)
        return -1;   /* errno already set (EAGAIN if ARP not resolved) */

    /* Mark query in-flight. */
    client->pending.active   = 1;
    client->pending.id       = id;
    client->pending.cb       = callback;
    client->pending.userdata = userdata;
    strncpy(client->pending.name, name, sizeof(client->pending.name) - 1);
    client->pending.name[sizeof(client->pending.name) - 1] = '\0';

    return 0;
}

int dns_is_pending(const DnsClient *client)
{
    return client ? client->pending.active : 0;
}

void dns_close(DnsClient *client)
{
    if (!client) return;
    rawket_udp_close(client->sock);
    free(client);
}
