/**
 * debian_http.c — Download a Debian 13 (trixie) package via HTTP using rawket.
 *
 * Usage (requires CAP_NET_RAW / root):
 *   sudo ./debian_http <interface> <package-name>
 *   sudo ./debian_http eth0 curl
 *
 * Flow:
 *   1. Generate random locally-administered MAC.
 *   2. Run DHCP on <interface> to obtain an IP, gateway, and DNS server.
 *   3. ARP-resolve the gateway (and DNS server if different) so that
 *      off-subnet traffic can flow.
 *   4. DNS-resolve deb.debian.org using the DHCP-supplied DNS server.
 *   5. HTTP GET dists/trixie/main/binary-amd64/Packages.gz, decompress on
 *      the fly, and stream-search for the requested package name to find
 *      its Filename field.
 *   6. HTTP GET the .deb URL and write it to <package>.deb, printing
 *      KB/s transfer rate every second.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <zlib.h>

#include "rawket.h"
#include "dhcp.h"
#include "dns.h"
#include "http.h"

/*
 * rawket is built with panic = "abort" so the EH personality function is never
 * called, but precompiled libcore objects still contain a DWARF reference to it.
 */
void rust_eh_personality(void) {}

/* ── Timing ─────────────────────────────────────────────────────────────────── */

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Ephemeral port range */
#define PORT_EPHEMERAL_BASE 20000u
#define PORT_EPHEMERAL_RANGE 20000u

/* Timing intervals (milliseconds) */
#define DNS_RESOLVE_TIMEOUT_MS   15000
#define ARP_RETRY_INTERVAL_MS    1000
#define RATE_REPORT_INTERVAL_MS  1000

/* zlib window bits for gzip decompression (RFC 1952) */
#define ZLIB_GZIP_WBITS  (16 + MAX_WBITS)

/* ── Random helpers ─────────────────────────────────────────────────────────── */

static void random_mac(uint8_t mac[6])
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0 && read(fd, mac, 6) == 6) {
        close(fd);
    } else {
        if (fd >= 0) close(fd);
        mac[0]=0x02; mac[1]=0xAA; mac[2]=0xBB;
        mac[3]=0xCC; mac[4]=0xDD; mac[5]=0xEE;
    }
    mac[0] = (mac[0] & 0xfe) | 0x02; /* locally administered, unicast */
}

static uint16_t random_port_base(void)
{
    uint16_t r = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, &r, sizeof(r)) != (ssize_t)sizeof(r))
            r = 0;  /* fallback: PORT_EPHEMERAL_BASE + 0 */
        close(fd);
    }
    return (uint16_t)(PORT_EPHEMERAL_BASE + (r % PORT_EPHEMERAL_RANGE));
}

/* ── DNS resolution ─────────────────────────────────────────────────────────── */

static uint32_t g_resolved_ip = 0;
static int      g_dns_done    = 0;

static void dns_cb(const char *name, uint32_t ip, void *ud)
{
    (void)name; (void)ud;
    g_resolved_ip = ip;
    g_dns_done    = 1;
}

/* ── Packages file stream-parser ─────────────────────────────────────────────── */

/*
 * The Debian Packages file is a sequence of stanzas separated by blank lines.
 * Each stanza has lines of the form "Field: value".  We search for the stanza
 * whose "Package:" field matches our target and extract its "Filename:" field.
 */
typedef struct {
    const char *target;
    char        linebuf[4096];
    int         linelen;
    int         in_block;       /* currently inside the target package stanza */
    char        filename[512];
    int         found;
} PkgState;

static int pkg_on_body(const uint8_t *data, size_t len, void *ud)
{
    PkgState       *ps  = ud;
    const uint8_t  *p   = data;
    const uint8_t  *end = data + len;

    if (ps->found) return -1;   /* abort: already have what we need */

    while (p < end) {
        char c = (char)*p++;
        if (c == '\n') {
            /* Strip trailing CR */
            if (ps->linelen > 0 && ps->linebuf[ps->linelen - 1] == '\r')
                ps->linelen--;
            ps->linebuf[ps->linelen] = '\0';

            if (ps->linelen == 0) {
                /* Blank line = stanza separator */
                ps->in_block = 0;
            } else if (strncmp(ps->linebuf, "Package: ", sizeof("Package: ") - 1) == 0) {
                ps->in_block = strcmp(ps->linebuf + sizeof("Package: ") - 1, ps->target) == 0;
            } else if (ps->in_block &&
                       strncmp(ps->linebuf, "Filename: ", sizeof("Filename: ") - 1) == 0) {
                snprintf(ps->filename, sizeof(ps->filename),
                         "%s", ps->linebuf + sizeof("Filename: ") - 1);
                ps->found = 1;
                return -1;      /* abort the stream */
            }
            ps->linelen = 0;
        } else {
            if (ps->linelen < (int)sizeof(ps->linebuf) - 1)
                ps->linebuf[ps->linelen++] = c;
        }
    }
    return 0;
}

/* ── Shared progress bar ─────────────────────────────────────────────────────── */

#define BAR_WIDTH 40

static void print_progress(size_t total, long content_length, double rate_kib)
{
    if (content_length > 0) {
        int filled = (int)((long long)total * BAR_WIDTH / content_length);
        if (filled > BAR_WIDTH) filled = BAR_WIDTH;
        int pct = (int)((long long)total * 100 / content_length);

        printf("\r  [");
        for (int i = 0; i < BAR_WIDTH; i++) {
            if      (i < filled)                         putchar('=');
            else if (i == filled && filled < BAR_WIDTH)  putchar('>');
            else                                         putchar(' ');
        }
        printf("] %3d%%  %.1f / %.1f KiB  %.1f KiB/s   ",
               pct, total / 1024.0, content_length / 1024.0, rate_kib);
    } else {
        printf("\r  %.1f KiB  %.1f KiB/s   ", total / 1024.0, rate_kib);
    }
    fflush(stdout);
}

/* ── Gzip-decompressing Packages body callback ───────────────────────────────── */

typedef struct {
    z_stream zs;
    int      init;
    PkgState *ps;
    uint8_t   out[65536];
    /* Progress (tracks compressed bytes received, matching Content-Length) */
    long    content_length;
    size_t  total;
    size_t  last_report;
    long    last_ms;
} GzipPkgState;

static int gz_pkg_on_body(const uint8_t *data, size_t len, void *ud)
{
    GzipPkgState *gs = ud;

    if (!gs->init) {
        memset(&gs->zs, 0, sizeof(gs->zs));
        if (inflateInit2(&gs->zs, ZLIB_GZIP_WBITS) != Z_OK) {
            fprintf(stderr, "inflateInit2 failed\n");
            return -1;
        }
        gs->init    = 1;
        gs->last_ms = now_ms();
    }

    gs->total += len;

    long now = now_ms();
    if (now - gs->last_ms >= RATE_REPORT_INTERVAL_MS) {
        double elapsed_s = (double)(now - gs->last_ms) / 1000.0;
        double rate_kib  = (double)(gs->total - gs->last_report) / elapsed_s / 1024.0;
        gs->last_report  = gs->total;
        gs->last_ms      = now;
        print_progress(gs->total, gs->content_length, rate_kib);
    }

    gs->zs.next_in  = (Bytef *)(uintptr_t)data;
    gs->zs.avail_in = (uInt)len;

    while (gs->zs.avail_in > 0) {
        gs->zs.next_out  = gs->out;
        gs->zs.avail_out = (uInt)sizeof(gs->out);

        int ret = inflate(&gs->zs, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
            fprintf(stderr, "inflate error: %d\n", ret);
            return -1;
        }

        size_t have = sizeof(gs->out) - gs->zs.avail_out;
        if (have > 0) {
            int r = pkg_on_body(gs->out, have, gs->ps);
            if (r < 0) return r;
        }

        if (ret == Z_STREAM_END) break;
    }
    return 0;
}

/* ── .deb download callback ─────────────────────────────────────────────────── */

typedef struct {
    FILE   *fp;
    long    content_length;   /* -1 until HTTP headers arrive */
    size_t  total;
    size_t  last_report;
    long    start_ms;
    long    last_ms;
} DebState;

static int deb_on_body(const uint8_t *data, size_t len, void *ud)
{
    DebState *ds = ud;

    if (fwrite(data, 1, len, ds->fp) != len) {
        fprintf(stderr, "\nWrite error: %s\n", strerror(errno));
        return -1;
    }
    ds->total += len;

    long now = now_ms();
    if (now - ds->last_ms < RATE_REPORT_INTERVAL_MS) return 0;

    double elapsed_s = (double)(now - ds->last_ms) / 1000.0;
    double rate_kib  = (double)(ds->total - ds->last_report) / elapsed_s / 1024.0;
    ds->last_report  = ds->total;
    ds->last_ms      = now;
    print_progress(ds->total, ds->content_length, rate_kib);
    return 0;
}

/* ── Main ───────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <package-name>\n", argv[0]);
        fprintf(stderr, "Example: sudo %s eth0 curl\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1];
    const char *pkg    = argv[2];

    /* ── 1. Network initialisation ─────────────────────────────────────────── */
    uint8_t mac[6];
    random_mac(mac);

    RawketNetwork *net = rawket_network_new(NULL);
    if (!net) { perror("rawket_network_new"); return 1; }

    int intf = rawket_network_add_intf(net, ifname, mac);
    if (intf < 0) { perror("rawket_network_add_intf"); return 1; }

    /* ── 2. DHCP ───────────────────────────────────────────────────────────── */
    printf("Running DHCP on %s ...\n", ifname);
    DhcpLease lease;
    if (dhcp_run(net, intf, mac, &lease) < 0) {
        fprintf(stderr, "DHCP failed\n");
        return 1;
    }
    {
        char ip_s[16], gw_s[16], dns_s[16];
        struct in_addr a;
        a.s_addr = lease.ip;         inet_ntop(AF_INET, &a, ip_s,  sizeof(ip_s));
        a.s_addr = lease.router;     inet_ntop(AF_INET, &a, gw_s,  sizeof(gw_s));
        a.s_addr = lease.dns_server; inet_ntop(AF_INET, &a, dns_s, sizeof(dns_s));
        printf("  Assigned: %s/%u  Gateway: %s  DNS: %s\n",
               ip_s, lease.prefix, gw_s, dns_s);
    }

    if (lease.router == 0) {
        fprintf(stderr, "No gateway in DHCP lease — cannot reach off-subnet hosts\n");
        return 1;
    }
    if (lease.dns_server == 0) {
        fprintf(stderr, "No DNS server in DHCP lease\n");
        return 1;
    }

    uint16_t port_base = random_port_base();

    /* ── 3. ARP-resolve gateway + DNS server, DNS-resolve deb.debian.org ───── */

    /* Open DNS client on an ephemeral port */
    DnsClient *dns = dns_open(net, intf, lease.ip, port_base++, lease.dns_server);
    if (!dns) { perror("dns_open"); return 1; }

    printf("Resolving deb.debian.org ...\n");

    g_dns_done    = 0;
    g_resolved_ip = 0;
    int dns_started = 0;
    long arp_next   = 0;
    long deadline   = now_ms() + DNS_RESOLVE_TIMEOUT_MS;

    while (now_ms() < deadline) {
        /* Periodically send ARP requests until the gateway MAC is cached. */
        long now = now_ms();
        if (now >= arp_next) {
            rawket_arp_request(net, intf, lease.router);
            if (lease.dns_server != lease.router)
                rawket_arp_request(net, intf, lease.dns_server);
            arp_next = now + ARP_RETRY_INTERVAL_MS;
        }

        rawket_network_poll_rx(net, 50);

        /* Start DNS query; retry on EAGAIN (ARP not yet resolved) */
        if (!dns_started) {
            if (dns_resolve(dns, "deb.debian.org", dns_cb, NULL) == 0)
                dns_started = 1;
            else if (errno != EAGAIN) {
                fprintf(stderr, "dns_resolve: %s\n", strerror(errno));
                break;
            }
        }

        if (g_dns_done) break;
    }

    if (!g_dns_done || g_resolved_ip == 0) {
        fprintf(stderr, "Could not resolve deb.debian.org\n");
        return 1;
    }
    {
        struct in_addr a; a.s_addr = g_resolved_ip;
        char ip_s[16]; inet_ntop(AF_INET, &a, ip_s, sizeof(ip_s));
        printf("  deb.debian.org → %s\n", ip_s);
    }

    uint32_t deb_ip = g_resolved_ip;
    dns_close(dns);

    /* ── 4. Search Packages index for the requested package ─────────────────── */

    printf("Searching Packages index for '%s' ...\n", pkg);
    printf("  (fetching dists/trixie/main/binary-amd64/Packages.gz — this may take a while)\n");

    PkgState ps;
    memset(&ps, 0, sizeof(ps));
    ps.target = pkg;

    GzipPkgState gps;
    memset(&gps, 0, sizeof(gps));
    gps.ps = &ps;

    int status = http_get_stream(
        net, intf, lease.ip, port_base++,
        deb_ip, "deb.debian.org",
        "/debian/dists/trixie/main/binary-amd64/Packages.gz",
        gz_pkg_on_body, &gps, &gps.content_length);

    if (gps.init) { inflateEnd(&gps.zs); printf("\n"); }

    if (status < 0) {
        fprintf(stderr, "HTTP error fetching Packages index\n");
        return 1;
    }
    if (status != 200) {
        fprintf(stderr, "Packages index returned HTTP %d\n", status);
        return 1;
    }
    if (!ps.found) {
        fprintf(stderr, "Package '%s' not found in trixie/main/amd64\n", pkg);
        return 1;
    }
    printf("  Found: %s\n", ps.filename);

    /* ── 5. Download the .deb ─────────────────────────────────────────────── */

    /* Build the URL path: /debian/<Filename field from Packages> */
    char url_path[600];
    int url_len = snprintf(url_path, sizeof(url_path), "/debian/%s", ps.filename);
    if (url_len <= 0 || url_len >= (int)sizeof(url_path)) {
        fprintf(stderr, "Package filename too long\n");
        return 1;
    }

    /* Output filename: basename of the path */
    const char *outname = ps.filename;
    for (const char *p2 = ps.filename; *p2; p2++)
        if (*p2 == '/') outname = p2 + 1;

    printf("Downloading %s ...\n", outname);

    FILE *fp = fopen(outname, "wb");
    if (!fp) { perror(outname); return 1; }

    DebState ds;
    memset(&ds, 0, sizeof(ds));
    ds.fp             = fp;
    ds.content_length = -1;
    ds.start_ms       = now_ms();
    ds.last_ms        = ds.start_ms;

    status = http_get_stream(
        net, intf, lease.ip, port_base++,
        deb_ip, "deb.debian.org",
        url_path,
        deb_on_body, &ds, &ds.content_length);

    fclose(fp);

    if (status < 0 || status != 200) {
        fprintf(stderr, "\nHTTP %d downloading %s\n", status, outname);
        unlink(outname);
        return 1;
    }

    double elapsed_s = (double)(now_ms() - ds.start_ms) / 1000.0;
    double avg_kib   = elapsed_s > 0.0
                       ? (double)ds.total / elapsed_s / 1024.0 : 0.0;
    printf("\n  Done: %s  %.1f KiB  %.1f KiB/s avg  %.1f s\n",
           outname, ds.total / 1024.0, avg_kib, elapsed_s);

    rawket_network_free(net);
    return 0;
}
