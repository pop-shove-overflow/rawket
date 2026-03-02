# rawket

A tiny userspace IPv4 stack for Linux, written in Rust (`no_std`), exposed as a C shared/static library.

## Features

- **AF_PACKET / TPACKET_V2** — zero-copy mmap RX/TX rings; no kernel TCP/IP involved
- **ARP** — request/reply, cache with TTL expiry and pending-queue for in-flight sends
- **IPv4** — receive, send, fragment reassembly, RFC 1071 checksum
- **ICMP** — unreachable replies, rate-limited
- **UDP** — socket API with automatic ARP resolution
- **TCP** — full RFC 793 state machine (all eleven states, TIME_WAIT 2×MSL) with:
  - **Window scaling** (RFC 1323) — shift-4 advertised window, up to 1 MiB receive buffer
  - **SACK** (RFC 2018) — receiver buffers up to 4 out-of-order blocks and echoes them; sender skips already-SACKed ranges on retransmit
  - **RACK loss detection** (RFC 8985) — a segment is declared lost when it is older than `SRTT + SRTT/4` and a later segment has been acknowledged; avoids unnecessary RTO waits after reordering
  - **Tail Loss Probe (TLP)** — when the retransmit timer has not fired but no ACK has arrived within `2×SRTT`, a probe segment is sent to trigger a fast recovery instead of a full RTO backoff
  - **RTT estimation** — Jacobson/Karels SRTT + RTTVAR; RTO clamped to a configurable [200 ms, 60 s] range with exponential backoff and a retransmit-count limit
  - **BBRv3 congestion control** — model-based, loss-signal-free pacing through four phases: *Startup* (exponential bandwidth probing, gain 2.88×), *Drain* (queue draining, gain 0.35×), *ProbeBw* (steady-state cycling), and *ProbeRtt* (periodic RTT refresh by reducing inflight to 4 MSS); bandwidth tracked with a windowed max filter; cwnd and pacing rate derived from estimated BDP; software pacing enforced per-MSS
- **Routing** — per-network routing table with longest-prefix match; nexthop resolved automatically
- **DoS mitigations** — ARP cache size cap, per-IP pending queue depth, ICMP token-bucket rate limit, fragment per-source limit, TCP send-buffer cap
- **Single dependency** — only `libc`; builds to a ~200 KiB stripped musl static library

## Building

```sh
make          # release: echo_server, debian_http, librawket.{a,so}
make debug    # debug:   debian_http_dbg, librawket.a (debug)
```

Requires Rust stable + `x86_64-unknown-linux-musl` target + `musl-gcc` + `zlib`.

## Examples

### `echo_server`

A peer-to-peer number-guessing game that demonstrates both the TCP server and client paths.

On startup it acquires an IP via DHCP, picks a random TCP port and a secret number in [1, 100], then broadcasts `RAWKET_ECHO:<port>` over UDP so other instances on the subnet can find it.  When two instances discover each other the numerically lower IP connects as the **client** and guesses the peer's number using binary search; the higher IP waits for the incoming connection and acts as the **server**, replying `HIGHER`, `LOWER`, or `CORRECT` to each guess.

```
sudo ./echo_server eth0
```

### `debian_http`

Downloads a Debian 13 (trixie) package from `deb.debian.org` entirely through the rawket stack — no kernel networking used.

Steps: DHCP → ARP-resolve gateway → DNS-resolve `deb.debian.org` → HTTP GET `Packages.gz` (streamed, gzip-decompressed on the fly) to find the package path → HTTP GET the `.deb` file, written to disk with a live progress bar.

```
sudo ./debian_http eth0 curl
```
