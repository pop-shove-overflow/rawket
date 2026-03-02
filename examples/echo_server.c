/**
 * echo_server.c — rawket TCP number-guessing game server/client.
 *
 * Usage:
 *   ./echo_server <interface>
 *
 * Behaviour:
 *   - Generates a random locally-administered MAC, runs DHCP.
 *   - Picks a random TCP port > 1024 and a secret number in [1, 100].
 *   - Broadcasts "RAWKET_ECHO:<port>\n" over UDP on ADV_PORT every
 *     ADV_INTERVAL_MS ms so other instances on the subnet can find it.
 *   - Also listens for peer advertisements (via the Ethernet tap); if another
 *     instance is found it sends an ARP request to resolve the peer's MAC,
 *     then connects and plays the guessing game as the CLIENT.
 *   - Stops broadcasting as soon as any TCP connection is established.
 *   - SERVER role: sends a coloured prompt; reads one guess per line; responds:
 *       HIGHER  (bright purple) — the secret is above the guess
 *       LOWER   (bright red)   — the secret is below the guess
 *       CORRECT (green)        — closes the connection
 *   - CLIENT role: guesses the peer's number with binary search;
 *     adjusts on HIGHER / LOWER; stops on CORRECT.
 *   - Every byte received via TCP is also written to stdout.
 *
 * Requires CAP_NET_RAW (run as root or grant the capability).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "rawket.h"
#include "dhcp.h"

/*
 * rawket is built with panic = "abort", so the EH personality function is
 * never called.  The precompiled libcore/liballoc objects still contain a
 * DWARF CFI reference to it, so we provide a no-op stub to satisfy the linker.
 */
void rust_eh_personality(void) {}

/* ── Constants ───────────────────────────────────────────────────────────── */

/* UDP port on which advertisement broadcasts are sent and received. */
#define ADV_PORT         7879u
/* Milliseconds between successive broadcast advertisements. */
#define ADV_INTERVAL_MS  30000

/* Ethernet / IPv4 / UDP frame constants */
#define ETH_ALEN            6
#define ETH_OFF_SRC         6
#define ETH_OFF_ETHERTYPE   12
#define ETHERTYPE_IPV4      0x0800u

#define IPV4_VER_IHL        0x45u   /* version=4, IHL=5 (no options) */
#define IP_DEFAULT_TTL      64
#define IPV4_HDR_LEN        20
#define IPV4_OFF_TOTLEN     2
#define IPV4_OFF_TTL        8
#define IPV4_OFF_PROTO      9
#define IPV4_OFF_CKSUM      10
#define IPV4_OFF_SRC        12
#define IPV4_OFF_DST        16

#define UDP_HDR_LEN         8
#define UDP_OFF_DPORT       2
#define UDP_OFF_LEN         4

/* Game range */
#define GAME_MIN    1
#define GAME_MAX    100

/* Ephemeral port range for TCP game sockets */
#define PORT_EPHEMERAL_MIN  1025u
#define PORT_EPHEMERAL_MAX  65000u

/* ── ANSI colour helpers ─────────────────────────────────────────────────── */

#define ART_RS    "\033[0m"   /* reset */
#define ART_R     "\033[91m"   /* bright red    */
#define ART_P  "\033[95m"   /* bright purple */
#define ART_G   "\033[92m"   /* bright green  */

/* ── Game messages ───────────────────────────────────────────────────────── */

static const char MSG_PROMPT[] =
    "Pick a number between " ART_R "1" ART_RS
    " and " ART_P "100" ART_RS "\n";

static const char MSG_HIGHER[]  = ART_P "HIGHER"  ART_RS "\n";
static const char MSG_LOWER[]   = ART_R    "LOWER"   ART_RS "\n";
static const char MSG_CORRECT[] = ART_G  "CORRECT" ART_RS "\n";

/* Lines starting with '#' are silently ignored by echo-server peers. */
#define ART_W  "\033[1;97m"   /* bold bright white  — nose tip         */
#define ART_C  "\033[1;96m"   /* bold bright cyan   — porthole         */
#define ART_S  "\033[37m"     /* silver/grey        — body             */
#define ART_DG "\033[90m"     /* dark grey          — shadow           */
#define ART_B  "\033[1;34m"   /* bold blue          — fins             */
#define ART_O  "\033[33m"     /* amber              — nozzles/exhaust  */
#define ART_Y  "\033[1;93m"   /* bold bright yellow — flame core       */
static const char MSG_ROCKET[] =
    "#\n"
    "#       " ART_W "/\\" ART_RS "\n"
    "#      " ART_C "(" ART_P "rw" ART_C ")" ART_RS "\n"
    "#      " ART_S "(" ART_P "kt" ART_S ")" ART_RS "\n"
    "#     " ART_B "/" ART_S "|" ART_W "/\\" ART_S "|" ART_B "\\" ART_RS "\n"
    "#    " ART_B "/_" ART_O "||||" ART_B "_\\" ART_RS "\n"
    "#      " ART_O ")  (" ART_RS "\n"
    "#     " ART_Y "/    \\" ART_RS "\n"
    "#      " ART_Y "\\  /" ART_RS "\n"
    "#       " ART_Y "\\/" ART_RS "\n"
    "#\n";

/* ── Frame-building helpers ───────────────────────────────────────────────── */

/* Write a big-endian uint16_t into buf at byte offset off. */
static void wr16(uint8_t *b, int off, uint16_t v)
{
    b[off]     = (uint8_t)(v >> 8);
    b[off + 1] = (uint8_t)(v);
}

/* RFC 1071 one's-complement checksum over buf[0..len). */
static uint16_t ip_cksum(const uint8_t *buf, int len)
{
    uint32_t sum = 0;
    while (len > 1) {
        sum += ((uint32_t)buf[0] << 8) | buf[1];
        buf += 2; len -= 2;
    }
    if (len) sum += (uint32_t)*buf << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* ── Broadcast advertisement ─────────────────────────────────────────────── */

/* Ethernet/IP/UDP frame offsets (no IP options). */
#define ADV_OFF_ETH  0
#define ADV_OFF_IP   (ADV_OFF_ETH + 14)
#define ADV_OFF_UDP  (ADV_OFF_IP  + IPV4_HDR_LEN)
#define ADV_OFF_DATA (ADV_OFF_UDP + UDP_HDR_LEN)

/*
 * Compute the directed subnet broadcast address (network byte order).
 */
static uint32_t subnet_bcast(uint32_t ip_nbo, uint8_t prefix)
{
    if (prefix == 0)   return htonl(0xffffffffu);
    if (prefix >= 32)  return ip_nbo;
    uint32_t ip   = ntohl(ip_nbo);
    uint32_t mask = ~0u << (32 - prefix);
    return htonl((ip & mask) | ~mask);
}

/* ── Global peer discovery state ─────────────────────────────────────────── */

static uint32_t g_own_ip    = 0;
static uint32_t g_peer_ip   = 0;
static uint16_t g_peer_port = 0;
static int      g_arp_sent  = 0;

static char g_me_prefix[48]   = "";
static char g_them_prefix[48] = "";

static void setup_prefixes(uint32_t own_ip, uint32_t peer_ip)
{
    char own_s[INET_ADDRSTRLEN], peer_s[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &own_ip, own_s, sizeof(own_s));
    if (peer_ip)
        inet_ntop(AF_INET, &peer_ip, peer_s, sizeof(peer_s));
    else
        memcpy(peer_s, "peer", sizeof("peer"));
    snprintf(g_me_prefix,   sizeof(g_me_prefix),   "[%s (me)]: ",   own_s);
    snprintf(g_them_prefix, sizeof(g_them_prefix),  "[%s (them)]: ", peer_s);
}

/* No-op tap callback — we open the tap only for sending. */
static void adv_tap_cb(const uint8_t *frame, size_t len, void *ud)
{
    (void)frame; (void)len; (void)ud;
}

/*
 * UDP receive callback: parse incoming "RAWKET_ECHO:<port>\n" advertisements.
 */
static void adv_udp_recv(const RawketUdpPacket *pkt, void *ud)
{
    (void)ud;

    if (pkt->ip_src == g_own_ip || g_peer_ip != 0)
        return;

    char buf[32];
    size_t n = pkt->pdu_len < sizeof(buf) - 1 ? pkt->pdu_len : sizeof(buf) - 1;
    memcpy(buf, pkt->pdu, n);
    buf[n] = '\0';

    if (strncmp(buf, "RAWKET_ECHO:", 12) != 0)
        return;
    int port = atoi(buf + 12);
    if (port < (int)PORT_EPHEMERAL_MIN || port > 65535)
        return;

    g_peer_ip   = pkt->ip_src;
    g_peer_port = (uint16_t)port;

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &g_peer_ip, ip_str, sizeof(ip_str));
    printf("Discovered peer at %s port %u\n", ip_str, (unsigned)g_peer_port);
    fflush(stdout);
}

/*
 * Build and transmit a UDP broadcast Ethernet frame advertising our TCP port.
 * Uses the Ethernet tap because broadcast IPs are never in the ARP cache.
 */
static void send_adv(RawketEthSocket *tap, const uint8_t mac[6],
                     uint32_t src_ip, uint32_t bcast_ip, uint16_t tcp_port)
{
    char payload[24];
    int  plen = snprintf(payload, sizeof(payload),
                         "RAWKET_ECHO:%u\n", (unsigned)tcp_port);
    if (plen <= 0 || plen >= (int)sizeof(payload))
        return;

    uint8_t frame[128];
    int     frame_len = ADV_OFF_DATA + plen;
    memset(frame, 0, (size_t)frame_len);

    memset(frame + ADV_OFF_ETH,              0xff, ETH_ALEN);
    memcpy(frame + ADV_OFF_ETH + ETH_OFF_SRC, mac, ETH_ALEN);
    wr16(frame, ADV_OFF_ETH + ETH_OFF_ETHERTYPE, ETHERTYPE_IPV4);

    frame[ADV_OFF_IP + IPV4_OFF_TTL]   = IP_DEFAULT_TTL;
    frame[ADV_OFF_IP + IPV4_OFF_PROTO] = IPPROTO_UDP;
    frame[ADV_OFF_IP]                  = IPV4_VER_IHL;
    wr16(frame, ADV_OFF_IP + IPV4_OFF_TOTLEN,
         (uint16_t)(frame_len - ADV_OFF_IP));
    memcpy(frame + ADV_OFF_IP + IPV4_OFF_SRC, &src_ip,   sizeof(uint32_t));
    memcpy(frame + ADV_OFF_IP + IPV4_OFF_DST, &bcast_ip, sizeof(uint32_t));
    wr16(frame, ADV_OFF_IP + IPV4_OFF_CKSUM,
         ip_cksum(frame + ADV_OFF_IP, IPV4_HDR_LEN));

    wr16(frame, ADV_OFF_UDP,                (uint16_t)ADV_PORT);
    wr16(frame, ADV_OFF_UDP + UDP_OFF_DPORT, (uint16_t)ADV_PORT);
    wr16(frame, ADV_OFF_UDP + UDP_OFF_LEN,   (uint16_t)(UDP_HDR_LEN + plen));

    memcpy(frame + ADV_OFF_DATA, payload, (size_t)plen);

    rawket_eth_send(tap, frame, (size_t)frame_len);
}

/* ── Misc helpers ────────────────────────────────────────────────────────── */

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int random_local_mac(uint8_t mac[6])
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { perror("open /dev/urandom"); return -1; }
    if (read(fd, mac, 6) != 6) { perror("read /dev/urandom"); close(fd); return -1; }
    close(fd);
    mac[0] = (mac[0] & 0xfe) | 0x02;
    return 0;
}

static uint16_t random_port(void)
{
    uint8_t buf[2];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 4242;
    if (read(fd, buf, sizeof(buf)) != (ssize_t)sizeof(buf)) {
        close(fd);
        return 4242;
    }
    close(fd);
    uint16_t r = (uint16_t)(((uint16_t)buf[0] << 8) | buf[1]);
    return (uint16_t)(PORT_EPHEMERAL_MIN + r % (PORT_EPHEMERAL_MAX - PORT_EPHEMERAL_MIN + 1u));
}

static int random_answer(void)
{
    uint8_t buf[1];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return (GAME_MIN + GAME_MAX) / 2;
    if (read(fd, buf, sizeof(buf)) != (ssize_t)sizeof(buf)) {
        close(fd);
        return (GAME_MIN + GAME_MAX) / 2;
    }
    close(fd);
    return GAME_MIN + (int)(buf[0] % (GAME_MAX - GAME_MIN + 1));
}

static int tcp_send_str(RawketTcpSocket *sock, const char *s)
{
    size_t len = strlen(s);
    const char *p = s, *end = s + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t seg = nl ? (size_t)(nl - p + 1) : (size_t)(end - p);
        if (p[0] == '#') {
            fwrite(p, 1, seg, stdout);
        } else {
            fputs(g_me_prefix, stdout);
            fwrite(p, 1, seg, stdout);
        }
        p += seg;
    }
    fflush(stdout);
    return rawket_tcp_send(sock, (const uint8_t *)s, len);
}

/* ── Game context ─────────────────────────────────────────────────────────── */

typedef enum { LOOP_NEXT = 0, LOOP_CONTINUE, LOOP_BREAK } LoopAction;

typedef struct {
    RawketNetwork   *net;
    RawketTcpSocket *tcp_server;
    RawketTcpSocket *tcp_client;
    RawketEthSocket *bcast_tap;
    RawketUdpSocket *adv_udp;

    uint8_t  mac[ETH_ALEN];
    uint32_t own_ip;
    uint32_t bcast_ip;
    uint16_t tcp_port;
    uint16_t cli_src_port;
    int      intf_idx;
    long     next_adv;

    int  answer;
    int  phase;
    long close_deadline;

    char line_buf[256];
    int  line_len;

    int cs_lo;
    int cs_hi;
    int cs_guess;
    int cs_sent_first;  /* 1 after the first guess has been sent */
} GameCtx;

/* ── Per-phase tick functions ─────────────────────────────────────────────── */

static void send_guess(RawketTcpSocket *sock, int guess)
{
    char gs[16];
    snprintf(gs, sizeof(gs), "%d\n", guess);
    tcp_send_str(sock, gs);
}

static LoopAction tick_advertising(GameCtx *ctx)
{
    if (ctx->tcp_server &&
        rawket_tcp_state(ctx->tcp_server) == RAWKET_TCP_ESTABLISHED) {
        rawket_eth_close(ctx->bcast_tap); ctx->bcast_tap = NULL;
        if (ctx->tcp_client) {
            rawket_tcp_close(ctx->tcp_client); ctx->tcp_client = NULL;
        }

        setup_prefixes(ctx->own_ip, g_peer_ip);
        ctx->line_len = 0;
        printf("TCP connection established (incoming) — SERVER role, answer: %d\n",
               ctx->answer);
        fflush(stdout);
        tcp_send_str(ctx->tcp_server, MSG_ROCKET);
        tcp_send_str(ctx->tcp_server, MSG_PROMPT);
        ctx->phase = 1;
        return LOOP_CONTINUE;
    }

    if (ctx->tcp_client) {
        int cli_st = rawket_tcp_state(ctx->tcp_client);
        if (cli_st == RAWKET_TCP_ESTABLISHED) {
            rawket_eth_close(ctx->bcast_tap); ctx->bcast_tap = NULL;
            rawket_tcp_close(ctx->tcp_server); ctx->tcp_server = NULL;

            setup_prefixes(ctx->own_ip, g_peer_ip);
            ctx->cs_lo    = GAME_MIN;
            ctx->cs_hi    = GAME_MAX;
            ctx->cs_guess = (GAME_MIN + GAME_MAX) / 2;
            ctx->line_len = 0;

            char peer_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &g_peer_ip, peer_str, sizeof(peer_str));
            printf("TCP connection established (outgoing to %s:%u) — CLIENT role\n",
                   peer_str, (unsigned)g_peer_port);
            fflush(stdout);
            ctx->phase = 2;
            return LOOP_CONTINUE;
        }
        if (cli_st == RAWKET_TCP_CLOSED) {
            rawket_tcp_close(ctx->tcp_client); ctx->tcp_client = NULL;
            g_peer_ip = 0; g_peer_port = 0;
            g_arp_sent = 0; ctx->cli_src_port = 0;
        }
    }

    if (g_peer_ip != 0 && ctx->tcp_client == NULL &&
        ntohl(ctx->own_ip) < ntohl(g_peer_ip)) {
        if (!g_arp_sent) {
            rawket_arp_request(ctx->net, ctx->intf_idx, g_peer_ip);
            g_arp_sent = 1;
        }
        if (ctx->cli_src_port == 0) {
            ctx->cli_src_port = random_port();
            char peer_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &g_peer_ip, peer_str, sizeof(peer_str));
            printf("Connecting to peer %s port %u...\n",
                   peer_str, (unsigned)g_peer_port);
            fflush(stdout);
        }

        ctx->tcp_client = rawket_tcp_connect(ctx->net,
                                             ctx->cli_src_port,
                                             g_peer_ip, g_peer_port,
                                             NULL, NULL, NULL, NULL);
        if (ctx->tcp_client == NULL && errno != EAGAIN) {
            perror("rawket_tcp_connect");
            g_peer_ip = 0; g_peer_port = 0;
            g_arp_sent = 0; ctx->cli_src_port = 0;
        }
    }

    long now = now_ms();
    if (ctx->bcast_tap && now >= ctx->next_adv) {
        send_adv(ctx->bcast_tap, ctx->mac, ctx->own_ip,
                 ctx->bcast_ip, ctx->tcp_port);
        ctx->next_adv = now + ADV_INTERVAL_MS;
    }

    return LOOP_NEXT;
}

static LoopAction tick_server(GameCtx *ctx)
{
    int st = rawket_tcp_state(ctx->tcp_server);
    if (st == RAWKET_TCP_CLOSE_WAIT) {
        printf("[client disconnected]\n");
        fflush(stdout);
        rawket_tcp_shutdown(ctx->tcp_server);
        ctx->close_deadline = now_ms() + 5000L;
        ctx->phase = 3;
        return LOOP_CONTINUE;
    }
    if (st == RAWKET_TCP_CLOSED) {
        printf("[connection reset by peer]\n");
        fflush(stdout);
        return LOOP_BREAK;
    }

    uint8_t buf[512];
    int n = rawket_tcp_recv(ctx->tcp_server, buf, sizeof(buf));
    while (n > 0) {
        for (int i = 0; i < n; i++) {
            char c = (char)buf[i];
            if (c == '\n') {
                while (ctx->line_len > 0 &&
                       ctx->line_buf[ctx->line_len - 1] == '\r')
                    ctx->line_len--;
                ctx->line_buf[ctx->line_len] = '\0';
                ctx->line_len = 0;

                if (ctx->line_buf[0] == '#') {
                    puts(ctx->line_buf);
                    continue;
                }

                printf("%s%s\n", g_them_prefix, ctx->line_buf);
                fflush(stdout);

                int guess = atoi(ctx->line_buf);
                if (guess < ctx->answer) {
                    tcp_send_str(ctx->tcp_server, MSG_HIGHER);
                } else if (guess > ctx->answer) {
                    tcp_send_str(ctx->tcp_server, MSG_LOWER);
                } else {
                    tcp_send_str(ctx->tcp_server, MSG_CORRECT);
                    rawket_tcp_shutdown(ctx->tcp_server);
                    ctx->close_deadline = now_ms() + 10000L;
                    ctx->phase = 3;
                    return LOOP_NEXT;
                }
            } else if (ctx->line_len < (int)sizeof(ctx->line_buf) - 1) {
                ctx->line_buf[ctx->line_len++] = c;
            }
        }
        if (ctx->phase == 3) break;
        n = rawket_tcp_recv(ctx->tcp_server, buf, sizeof(buf));
    }
    return LOOP_NEXT;
}

static LoopAction tick_client(GameCtx *ctx)
{
    int st = rawket_tcp_state(ctx->tcp_client);
    if (st == RAWKET_TCP_CLOSE_WAIT) {
        printf("[server disconnected]\n");
        fflush(stdout);
        rawket_tcp_shutdown(ctx->tcp_client);
        ctx->close_deadline = now_ms() + 5000L;
        ctx->phase = 3;
        return LOOP_CONTINUE;
    }
    if (st == RAWKET_TCP_CLOSED) {
        printf("[connection reset by peer]\n");
        fflush(stdout);
        return LOOP_BREAK;
    }

    uint8_t buf[512];
    int n = rawket_tcp_recv(ctx->tcp_client, buf, sizeof(buf));
    while (n > 0) {
        for (int i = 0; i < n; i++) {
            char c = (char)buf[i];
            if (c == '\n') {
                while (ctx->line_len > 0 &&
                       ctx->line_buf[ctx->line_len - 1] == '\r')
                    ctx->line_len--;
                ctx->line_buf[ctx->line_len] = '\0';
                ctx->line_len = 0;

                if (ctx->line_buf[0] == '#') {
                    puts(ctx->line_buf);
                    continue;
                }

                printf("%s%s\n", g_them_prefix, ctx->line_buf);
                fflush(stdout);

                if (strstr(ctx->line_buf, "CORRECT")) {
                    printf("[guessed correctly!]\n");
                    fflush(stdout);
                    rawket_tcp_shutdown(ctx->tcp_client);
                    ctx->close_deadline = now_ms() + 10000L;
                    ctx->phase = 3;
                    return LOOP_NEXT;
                } else if (strstr(ctx->line_buf, "HIGHER")) {
                    ctx->cs_lo    = ctx->cs_guess + 1;
                    ctx->cs_guess = (ctx->cs_lo + ctx->cs_hi) / 2;
                    send_guess(ctx->tcp_client, ctx->cs_guess);
                } else if (strstr(ctx->line_buf, "LOWER")) {
                    ctx->cs_hi    = ctx->cs_guess - 1;
                    ctx->cs_guess = (ctx->cs_lo + ctx->cs_hi) / 2;
                    send_guess(ctx->tcp_client, ctx->cs_guess);
                } else if (!ctx->cs_sent_first) {
                    /* First non-comment, non-response line: send initial guess. */
                    ctx->cs_sent_first = 1;
                    send_guess(ctx->tcp_client, ctx->cs_guess);
                }
            } else if (ctx->line_len < (int)sizeof(ctx->line_buf) - 1) {
                ctx->line_buf[ctx->line_len++] = c;
            }
        }
        if (ctx->phase == 3) break;
        n = rawket_tcp_recv(ctx->tcp_client, buf, sizeof(buf));
    }
    return LOOP_NEXT;
}

static LoopAction tick_closing(const GameCtx *ctx)
{
    const RawketTcpSocket *active =
        ctx->tcp_server ? ctx->tcp_server : ctx->tcp_client;
    int st = active ? rawket_tcp_state(active) : RAWKET_TCP_CLOSED;
    if (st == RAWKET_TCP_CLOSED || now_ms() >= ctx->close_deadline)
        return LOOP_BREAK;
    return LOOP_NEXT;
}

/* ── Event loop ───────────────────────────────────────────────────────────── */

static void run_game_loop(GameCtx *ctx)
{
    for (;;) {
        /* rawket_network_poll_rx drives RX, timers, TCP retransmits, and
         * error callbacks automatically. */
        if (rawket_network_poll_rx(ctx->net, 100) < 0) {
            perror("rawket_network_poll_rx");
            break;
        }

        LoopAction action;
        switch (ctx->phase) {
        case 0:  action = tick_advertising(ctx); break;
        case 1:  action = tick_server(ctx);      break;
        case 2:  action = tick_client(ctx);      break;
        default: action = tick_closing(ctx);     break;
        }
        if (action == LOOP_BREAK)    break;
        if (action == LOOP_CONTINUE) continue;
    }
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n  e.g. %s eth0\n",
                argv[0], argv[0]);
        return 1;
    }
    const char *ifname = argv[1];

    GameCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.cs_lo    = GAME_MIN;
    ctx.cs_hi    = GAME_MAX;
    ctx.cs_guess = (GAME_MIN + GAME_MAX) / 2;

    if (random_local_mac(ctx.mac) < 0)
        return 1;

    printf("interface : %s\n", ifname);
    printf("MAC       : %02x:%02x:%02x:%02x:%02x:%02x\n",
           ctx.mac[0], ctx.mac[1], ctx.mac[2],
           ctx.mac[3], ctx.mac[4], ctx.mac[5]);
    fflush(stdout);

    /* ── Network stack ───────────────────────────────────────────────── */

    RawketNetworkConfig cfg = rawket_network_config_default();
    ctx.net = rawket_network_new(&cfg);
    if (!ctx.net) { perror("rawket_network_new"); return 1; }

    ctx.intf_idx = rawket_network_add_intf(ctx.net, ifname, ctx.mac);
    if (ctx.intf_idx < 0) { perror("rawket_network_add_intf"); return 1; }

    /* ── DHCP ────────────────────────────────────────────────────────── */

    DhcpLease lease;
    if (dhcp_run(ctx.net, ctx.intf_idx, ctx.mac, &lease) < 0)
        return 1;

    ctx.own_ip = lease.ip;
    g_own_ip   = lease.ip;

    {
        char ip_str[INET_ADDRSTRLEN], gw_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &lease.ip,     ip_str, sizeof(ip_str));
        inet_ntop(AF_INET, &lease.router, gw_str, sizeof(gw_str));
        printf("address   : %s/%u\n", ip_str, lease.prefix);
        if (lease.router != 0) printf("gateway   : %s\n", gw_str);
        printf("lease     : %us\n", lease.lease_s);
        fflush(stdout);
    }

    /* ── Game setup ──────────────────────────────────────────────────── */

    ctx.tcp_port = random_port();
    ctx.answer   = random_answer();
    ctx.bcast_ip = subnet_bcast(lease.ip, lease.prefix);

    printf("TCP port  : %u\n", (unsigned)ctx.tcp_port);
    printf("Waiting for a player on the subnet...\n\n");
    fflush(stdout);

    /* Passive TCP socket — starts in LISTEN. */
    ctx.tcp_server = rawket_tcp_listen(ctx.net, lease.ip, ctx.tcp_port,
                                       NULL, NULL, NULL, NULL);
    if (!ctx.tcp_server) { perror("rawket_tcp_listen"); return 1; }

    /* UDP socket for receiving peer advertisements. */
    ctx.adv_udp = rawket_udp_open(ctx.net, ctx.intf_idx, lease.ip, ADV_PORT,
                                   adv_udp_recv, NULL);
    if (!ctx.adv_udp) { perror("rawket_udp_open"); return 1; }

    /* Ethernet tap — send-only; used for UDP broadcast advertisements. */
    ctx.bcast_tap = rawket_open_eth_cb(ctx.net, ctx.intf_idx, adv_tap_cb, NULL);
    if (!ctx.bcast_tap) { perror("rawket_open_eth_cb"); return 1; }

    /* ── Run ─────────────────────────────────────────────────────────── */

    run_game_loop(&ctx);

    /* ── Cleanup ─────────────────────────────────────────────────────── */

    if (ctx.bcast_tap)  rawket_eth_close(ctx.bcast_tap);
    if (ctx.adv_udp)    rawket_udp_close(ctx.adv_udp);
    if (ctx.tcp_server) rawket_tcp_close(ctx.tcp_server);
    if (ctx.tcp_client) rawket_tcp_close(ctx.tcp_client);
    rawket_network_free(ctx.net);
    return 0;
}
