/* vi: set sw=4 ts=4: */
/*
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
#ifndef UDHCP_DHCPD_H
#define UDHCP_DHCPD_H 1

#include <lwip/opt.h>

#ifndef UDHCP_DEBUG
#define UDHCP_DEBUG LWIP_DBG_OFF
#endif

/* Defaults you may want to tweak */
/* Default max_lease_sec */
#define DEFAULT_LEASE_TIME      (60*60*24 * 10)

struct udp_pcb;

typedef uint32_t leasetime_t;

struct dyn_lease {
	/* Unix time when lease expires.  */
	leasetime_t expires;
	/* "nip": IP in network order */
	uint32_t lease_nip;
	/* We use lease_mac[6], since e.g. ARP probing uses
	 * only 6 first bytes anyway. We check received dhcp packets
	 * that their hlen == 6 and thus chaddr has only 6 significant bytes
	 * (dhcp packet has chaddr[16], not [6])
	 */
	uint8_t lease_mac[6];
};

struct udhcpd_server {
	struct udp_pcb *pcb;
	uint16_t port;
	struct option_set *options;     /* list of DHCP options loaded from the config file */
	/* start,end are in host order: we need to compare start <= ip <= end */
	uint32_t start_ip;              /* start address of leases, in host order */
	uint32_t end_ip;                /* end of leases, in host order */
	uint32_t max_lease_sec;         /* maximum lease time (host order) */
	uint32_t min_lease_sec;         /* minimum lease time a client can request */
	uint32_t max_leases;            /* maximum number of leases (including reserved addresses) */
	uint32_t decline_time;          /* how long an address is reserved if a client returns a
	                                 * decline message */
	uint32_t offer_time;            /* how long an offered address is reserved */
	uint32_t siaddr_nip;            /* "next server" bootp option */
	char *sname;                    /* bootp server name */
	char *boot_file;                /* bootp boot file option */
	struct dyn_lease *leases;
};

struct udhcpd_server *udhcpd_init(const struct netif *netif, uint16_t port);

#endif
