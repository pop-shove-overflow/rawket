/**
 * http.h — Minimal HTTP/1.1 GET client built on rawket TCP.
 *
 * Usage:
 *   Call http_get_stream() with a body callback.  The function handles TCP
 *   connection, request sending, header parsing, and body delivery.
 *
 *   The callback returns 0 to continue receiving or -1 to abort the transfer
 *   early (the TCP connection is closed from our end immediately).
 *
 * Supports:
 *   - Content-Length responses
 *   - Transfer-Encoding: chunked responses
 *   - Early abort via callback return value
 *
 * IP addresses are in network byte order throughout.
 * Port numbers are in host byte order throughout.
 */
#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>
#include <stdint.h>
#include "rawket.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Body delivery callback.
 *
 * Called once per received chunk with a slice of the response body.
 * `data` and `len` are valid only for the duration of the call.
 *
 * @return  0  to continue receiving
 *          -1 to abort the download (connection closed immediately)
 */
typedef int (*http_body_fn)(const uint8_t *data, size_t len, void *userdata);

/**
 * Perform an HTTP/1.1 GET and stream the response body via `on_body`.
 *
 * Opens a fresh TCP connection for each call, sends a GET request with
 * "Connection: close", parses the response headers, and delivers the body
 * to `on_body` in whatever chunks rawket TCP provides.
 *
 * @param net        rawket network handle
 * @param intf_idx   uplink index from rawket_network_add_intf()
 * @param src_ip     source IPv4 address (network byte order)
 * @param src_port   ephemeral TCP source port (host byte order); must be
 *                   unique — no two concurrent HTTP calls may share a port
 * @param server_ip  destination IPv4 address (network byte order)
 * @param host       HTTP Host header value (e.g. "deb.debian.org")
 * @param path       Request path starting with '/' (e.g. "/debian/Release")
 * @param on_body    Called for each body chunk; may be NULL to discard body
 * @param userdata   Forwarded unchanged to each on_body invocation
 * @return           HTTP status code on success (e.g. 200, 404),
 *                   -1 on network / timeout error
 */
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
    long          *content_length_out  /**< filled before first on_body call; NULL OK */
);

#ifdef __cplusplus
}
#endif
#endif /* HTTP_H */
