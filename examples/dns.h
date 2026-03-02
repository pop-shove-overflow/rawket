/**
 * dns.h — Minimal async DNS-A client built on rawket UDP sockets.
 *
 * Usage:
 *   1. Call rawket_network_attach_iface() before dns_open().
 *   2. Call dns_open() to allocate a client and register a UDP socket on
 *      src_port with the rawket network for receive dispatch.
 *   3. Call dns_resolve() to send a DNS A-record query.  The callback fires
 *      when the answer arrives inside rawket_network_poll_rx().
 *   4. Only one query may be in flight at a time; call dns_is_pending() to
 *      check before issuing a new one.
 *   5. Call dns_close() to free the client.  The underlying UDP socket is
 *      owned by the rawket network and is not closed.
 *
 * IP addresses are in network byte order throughout.
 * Port numbers are in host byte order throughout.
 */
#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include "rawket.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DnsClient DnsClient;

/**
 * Callback invoked when a DNS A-record response arrives.
 *
 * @param name      The hostname that was queried (NUL-terminated).
 * @param ip        Resolved IPv4 address in network byte order, or 0 on
 *                  NXDOMAIN / SERVFAIL / parse error.
 * @param userdata  The pointer passed to dns_resolve().
 */
typedef void (*dns_resolve_fn)(const char *name, uint32_t ip, void *userdata);

/**
 * Allocate a DNS client and register a UDP socket on src_port.
 *
 * rawket_network_attach_iface() must have been called for an interface whose
 * IP is src_ip before calling this function.
 *
 * @param net        Network handle from rawket_network_new()
 * @param uplink     Uplink index from rawket_network_add_uplink()
 * @param src_ip     Source IPv4 address (network byte order)
 * @param src_port   Source UDP port used as the ephemeral client port
 * @param dns_server DNS server IPv4 address (network byte order)
 * @return           Opaque handle, or NULL on failure (errno set)
 */
DnsClient *dns_open(RawketNetwork *net, int uplink,
                    uint32_t src_ip, uint16_t src_port,
                    uint32_t dns_server);

/**
 * Send a DNS A-record query for name.
 *
 * Returns -1 with errno=EBUSY  if a previous query is still in flight.
 * Returns -1 with errno=EINVAL if name is malformed or too long.
 * Returns -1 with errno=EAGAIN if the destination MAC is not yet in the ARP
 *   cache; call again after rawket_network_poll_rx() has processed more frames.
 *
 * @param client   Handle from dns_open()
 * @param name     Hostname to resolve (e.g. "example.com")
 * @param callback Invoked when the reply arrives
 * @param userdata Forwarded unchanged to callback
 * @return         0 on success (query sent), -1 on error
 */
int dns_resolve(DnsClient *client, const char *name,
                dns_resolve_fn callback, void *userdata);

/**
 * Return non-zero if a query is currently in flight.
 */
int dns_is_pending(const DnsClient *client);

/**
 * Free the DnsClient.
 *
 * The underlying UDP socket is owned by the rawket network and continues to
 * exist; calling this while a query is in flight results in undefined
 * behaviour if the response arrives after dns_close() returns.
 */
void dns_close(DnsClient *client);

#ifdef __cplusplus
}
#endif
#endif /* DNS_H */
