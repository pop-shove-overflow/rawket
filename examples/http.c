/**
 * http.c — HTTP/1.1 GET client built on rawket TCP.
 */
#include "http.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Timing helper ──────────────────────────────────────────────────────────── */

static long http_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ── Constants ──────────────────────────────────────────────────────────────── */

#define HTTP_PORT         80u
#define CONNECT_TIMEOUT   10000   /* ms to establish TCP connection */
#define RESPONSE_TIMEOUT  120000  /* ms to receive full response    */
#define RECV_BUF          65536   /* bytes drained per recv call    */
#define HEADER_MAX        16384   /* max accumulated header bytes   */

/* ── Case-insensitive prefix match ─────────────────────────────────────────── */

static int iprefix(const char *s, const char *prefix)
{
    while (*prefix) {
        if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix)) return 0;
        s++; prefix++;
    }
    return 1;
}

/* ── End-of-headers search ──────────────────────────────────────────────────── */

static const char *find_hdr_end(const char *buf, int len)
{
    for (int i = 0; i + 3 < len; i++) {
        if (buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r' && buf[i+3]=='\n')
            return buf + i + 4;
    }
    return NULL;
}

/* ── HTTP response state ────────────────────────────────────────────────────── */

typedef struct {
    /* Header accumulation */
    char hdr[HEADER_MAX];
    int  hdr_len;
    int  hdr_done;

    /* Parsed values */
    int   status;
    int   chunked;
    long  clen;           /* Content-Length; -1 = unknown */

    /* Body tracking */
    size_t body_recv;
    int    done;
    int    aborted;

    /* Chunked decoder state */
    int  chunk_st;        /* 0=size line, 1=data, 2=trailing CRLF */
    long chunk_rem;
    char chunk_hdr[24];
    int  chunk_hdr_len;

    /* Callback */
    http_body_fn on_body;
    void        *userdata;

    /* Output: written before the first on_body call; NULL = ignored */
    long *content_length_out;
} HttpState;

/* ── Header parser ──────────────────────────────────────────────────────────── */

static void parse_headers(HttpState *s)
{
    const char *p   = s->hdr;
    const char *end = s->hdr + s->hdr_len;

    /* Status line: "HTTP/1.x NNN ..." */
    if (end - p < (ptrdiff_t)(sizeof("HTTP/1.x 200") - 1) || strncmp(p, "HTTP/1.", 7) != 0) return;
    p += sizeof("HTTP/1.x ") - 1;  /* skip version + space */
    char *endp;
    s->status = (int)strtol(p, &endp, 10);
    if (endp == p) return;  /* no digits — malformed status line */

    /* Advance past first \n */
    const char *nl = memchr(p, '\n', end - p);
    if (!nl) return;
    p = nl + 1;

    s->clen    = -1;
    s->chunked = 0;

    while (p < end) {
        const char *eol = memchr(p, '\n', end - p);
        if (!eol) break;
        int ll = (int)(eol - p);
        if (ll > 0 && p[ll - 1] == '\r') ll--;
        if (ll == 0) break;  /* blank line */

        if (iprefix(p, "content-length:")) {
            const char *v = p + sizeof("content-length:") - 1;
            while (v < p + ll && *v == ' ') v++;
            s->clen = strtol(v, NULL, 10);
        } else if (iprefix(p, "transfer-encoding:")) {
            const char *v = p + sizeof("transfer-encoding:") - 1;
            while (v < p + ll && *v == ' ') v++;
            if (iprefix(v, "chunked")) s->chunked = 1;
        }
        p = eol + 1;
    }
}

/* ── Body delivery helpers ──────────────────────────────────────────────────── */

static void deliver(HttpState *s, const uint8_t *data, size_t len)
{
    if (s->done || s->aborted || len == 0) return;
    if (s->clen >= 0) {
        long rem = s->clen - (long)s->body_recv;
        if (rem <= 0) { s->done = 1; return; }
        if ((long)len > rem) len = (size_t)rem;
    }
    if (s->on_body && s->on_body(data, len, s->userdata) < 0) {
        s->aborted = 1;
        return;
    }
    s->body_recv += len;
    if (s->clen >= 0 && (long)s->body_recv >= s->clen) s->done = 1;
}

static void deliver_chunked(HttpState *s, const uint8_t *data, size_t len)
{
    const uint8_t *p   = data;
    const uint8_t *end = data + len;

    while (p < end && !s->done && !s->aborted) {
        if (s->chunk_st == 0) {
            /* Accumulate hex size line */
            while (p < end) {
                char c = (char)*p++;
                if (c == '\n') {
                    s->chunk_hdr[s->chunk_hdr_len] = '\0';
                    s->chunk_rem     = strtol(s->chunk_hdr, NULL, 16);
                    s->chunk_hdr_len = 0;
                    if (s->chunk_rem == 0) { s->done = 1; return; }
                    s->chunk_st = 1;
                    break;
                }
                if (c != '\r' && s->chunk_hdr_len < (int)sizeof(s->chunk_hdr) - 1)
                    s->chunk_hdr[s->chunk_hdr_len++] = c;
            }
        } else if (s->chunk_st == 1) {
            /* Deliver chunk data */
            size_t avail = (size_t)(end - p);
            size_t take  = avail < (size_t)s->chunk_rem ? avail : (size_t)s->chunk_rem;
            if (take > 0) {
                deliver(s, p, take);
                p              += take;
                s->chunk_rem   -= (long)take;
            }
            if (s->chunk_rem == 0) s->chunk_st = 2;
        } else {
            /* Skip trailing CRLF after chunk data */
            while (p < end && (*p == '\r' || *p == '\n')) p++;
            if (p < end) s->chunk_st = 0;
        }
    }
}

/* ── Feed raw bytes into the HTTP state machine ─────────────────────────────── */

static void http_feed(HttpState *s, const uint8_t *data, size_t len)
{
    if (s->done || s->aborted) return;

    if (!s->hdr_done) {
        /* Accumulate into header buffer */
        size_t copy = len;
        if (s->hdr_len + (int)copy > HEADER_MAX)
            copy = (size_t)(HEADER_MAX - s->hdr_len);
        memcpy(s->hdr + s->hdr_len, data, copy);
        s->hdr_len += (int)copy;

        const char *hend = find_hdr_end(s->hdr, s->hdr_len);
        if (!hend) return;  /* headers incomplete */

        int hdr_total = (int)(hend - s->hdr);
        parse_headers(s);
        s->hdr_done = 1;
        if (s->content_length_out)
            *s->content_length_out = s->clen;

        /* Body bytes already in hdr[] after the header block */
        size_t body_in_hdr = (size_t)(s->hdr_len - hdr_total);
        if (body_in_hdr > 0) {
            if (s->chunked)
                deliver_chunked(s, (const uint8_t *)s->hdr + hdr_total, body_in_hdr);
            else
                deliver(s, (const uint8_t *)s->hdr + hdr_total, body_in_hdr);
        }

        /* Bytes from data[] that did not fit in hdr[] */
        if (copy < len) {
            if (s->chunked)
                deliver_chunked(s, data + copy, len - copy);
            else
                deliver(s, data + copy, len - copy);
        }
        return;
    }

    if (s->chunked)
        deliver_chunked(s, data, len);
    else
        deliver(s, data, len);
}

/* ── Public API ─────────────────────────────────────────────────────────────── */

int http_get_stream(
    RawketNetwork *net,
    int            intf_idx,
    uint32_t       src_ip,
    uint16_t       src_port,
    uint32_t       server_ip,
    const char    *host,
    const char    *path,
    http_body_fn   on_body,
    void          *userdata,
    long          *content_length_out)
{
    (void)intf_idx;  /* uplink selection handled by rawket routing */
    (void)src_ip;    /* source IP selected automatically via route lookup */

    /* ── 1. TCP connect ────────────────────────────────────────────────────── */
    RawketTcpSocket *sock = NULL;
    long deadline = http_now_ms() + CONNECT_TIMEOUT;

    while (http_now_ms() < deadline) {
        sock = rawket_tcp_connect(net, src_port,
                                  server_ip, HTTP_PORT,
                                  NULL, NULL, NULL, NULL);
        if (sock) break;
        if (errno != EAGAIN) return -1;
        rawket_network_poll_rx(net, 50);
    }
    if (!sock) return -1;

    /* ── 2. Wait for ESTABLISHED ───────────────────────────────────────────── */
    deadline = http_now_ms() + CONNECT_TIMEOUT;
    while (http_now_ms() < deadline) {
        rawket_network_poll_rx(net, 50);
        int st = rawket_tcp_state(sock);
        if (st == RAWKET_TCP_ESTABLISHED) break;
        if (st == RAWKET_TCP_CLOSED) { rawket_tcp_close(sock); return -1; }
    }
    if (rawket_tcp_state(sock) != RAWKET_TCP_ESTABLISHED) {
        rawket_tcp_close(sock);
        return -1;
    }

    /* ── 3. Send GET request ───────────────────────────────────────────────── */
    char req[1024];
    int  req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: rawket/0.1\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host);
    if (req_len <= 0 || req_len >= (int)sizeof(req)) {
        rawket_tcp_close(sock);
        return -1;
    }

    if (rawket_tcp_send(sock, (const uint8_t *)req, (size_t)req_len) < 0) {
        rawket_tcp_close(sock);
        return -1;
    }

    /* ── 4. Receive response ───────────────────────────────────────────────── */
    HttpState s;
    memset(&s, 0, sizeof(s));
    s.clen               = -1;
    s.on_body            = on_body;
    s.userdata           = userdata;
    s.content_length_out = content_length_out;

    static uint8_t recv_buf[RECV_BUF];
    deadline = http_now_ms() + RESPONSE_TIMEOUT;

    while (http_now_ms() < deadline && !s.done && !s.aborted) {
        rawket_network_poll_rx(net, 50);

        /* Drain all frames the ring accumulated during the wait. */
        for (;;) {
            int n = rawket_tcp_recv(sock, recv_buf, sizeof(recv_buf));
            if (n > 0) http_feed(&s, recv_buf, (size_t)n);

            int st = rawket_tcp_state(sock);
            if (st == RAWKET_TCP_CLOSE_WAIT ||
                st == RAWKET_TCP_CLOSED     ||
                st == RAWKET_TCP_FIN_WAIT2  ||
                st == RAWKET_TCP_TIME_WAIT) {
                /* Server done sending — drain recv_buf and finish. */
                while ((n = rawket_tcp_recv(sock, recv_buf, sizeof(recv_buf))) > 0)
                    http_feed(&s, recv_buf, (size_t)n);
                s.done = 1;
            }

            if (s.done || s.aborted || n <= 0) break;
        }
    }

    /* ── 5. Close connection ───────────────────────────────────────────────── */
    rawket_tcp_close(sock);

    return s.hdr_done ? s.status : -1;
}
