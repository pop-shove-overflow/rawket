#ifndef DHCP_H
#define DHCP_H

#include <stdint.h>
#include "rawket.h"

/**
 * Lease obtained from a DHCP server.  All IPv4 addresses are in network
 * byte order.  Fields with no corresponding option are left at 0.
 */
typedef struct {
    uint32_t ip;         /* assigned address                         */
    uint8_t  prefix;     /* CIDR prefix length                       */
    uint32_t router;     /* default gateway (0 if absent)            */
    uint32_t dns_server; /* first DNS server from option 6 (0 if absent) */
    uint32_t lease_s;    /* lease duration in seconds                */
} DhcpLease;

/**
 * Run DHCP DISCOVER → OFFER → REQUEST → ACK on `intf_idx`.
 *
 * Opens an Ethernet tap internally, performs up to 3 DISCOVER attempts
 * (4 s timeout each), sends REQUEST, waits for ACK, then closes the tap
 * and assigns the leased IP to the interface via rawket_intf_assign_ip().
 *
 * @param net       Network handle (rawket_network_add_intf already called)
 * @param intf_idx  Interface index returned by rawket_network_add_intf()
 * @param mac       Client hardware address (6 bytes)
 * @param lease     Filled on success
 * @return          0 on success, -1 on failure (message printed to stderr)
 */
int dhcp_run(RawketNetwork *net, int intf_idx,
             const uint8_t mac[6], DhcpLease *lease);

#endif /* DHCP_H */
