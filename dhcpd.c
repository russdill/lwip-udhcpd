/* vi: set sw=4 ts=4: */
/*
 * udhcp server
 * Copyright (C) 1999 Matthew Ramsay <matthewr@moreton.com.au>
 *			Chris Trew <ctrew@moreton.com.au>
 *
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <netinet/ether.h>
#include <arpa/inet.h>

#include <time.h>

#include <lwip/udp.h>

#include "udhcp_common.h"
#include "dhcpd.h"

/* Find the oldest expired lease, NULL if there are no expired leases */
static struct dyn_lease *oldest_expired_lease(struct udhcpd_server *server)
{
	struct dyn_lease *oldest_lease = NULL;
	leasetime_t oldest_time = time(NULL);
	unsigned i;

	/* Unexpired leases have server->leases[i].expires >= current time
	 * and therefore can't ever match */
	for (i = 0; i < server->max_leases; i++) {
		if (server->leases[i].expires == 0 /* empty entry */
		 || server->leases[i].expires < oldest_time
		) {
			oldest_time = server->leases[i].expires;
			oldest_lease = &server->leases[i];
		}
	}
	return oldest_lease;
}

/* Clear out all leases with matching nonzero chaddr OR yiaddr.
 * If chaddr == NULL, this is a conflict lease.
 */
static void clear_leases(struct udhcpd_server *server, const uint8_t *chaddr, uint32_t yiaddr)
{
	unsigned i;

	for (i = 0; i < server->max_leases; i++) {
		if ((chaddr && memcmp(server->leases[i].lease_mac, chaddr, 6) == 0)
		 || (yiaddr && server->leases[i].lease_nip == yiaddr)
		) {
			memset(&server->leases[i], 0, sizeof(server->leases[i]));
		}
	}
}

/* Add a lease into the table, clearing out any old ones.
 * If chaddr == NULL, this is a conflict lease.
 */
static struct dyn_lease *add_lease(struct udhcpd_server *server,
		const uint8_t *chaddr, uint32_t yiaddr,
		leasetime_t leasetime)
{
	struct dyn_lease *oldest;

	/* clean out any old ones */
	clear_leases(server, chaddr, yiaddr);

	oldest = oldest_expired_lease(server);

	if (oldest) {
		memset(oldest, 0, sizeof(*oldest));
		if (chaddr)
			memcpy(oldest->lease_mac, chaddr, 6);
		oldest->lease_nip = yiaddr;
		oldest->expires = time(NULL) + leasetime;
	}

	return oldest;
}

/* True if a lease has expired */
static int is_expired_lease(struct dyn_lease *lease)
{
	return (lease->expires < (leasetime_t) time(NULL));
}

/* Find the first lease that matches MAC, NULL if no match */
static struct dyn_lease *find_lease_by_mac(struct udhcpd_server *server, const uint8_t *mac)
{
	unsigned i;

	for (i = 0; i < server->max_leases; i++)
		if (memcmp(server->leases[i].lease_mac, mac, 6) == 0)
			return &server->leases[i];

	return NULL;
}

/* Find the first lease that matches IP, NULL is no match */
static struct dyn_lease *find_lease_by_nip(struct udhcpd_server *server, uint32_t nip)
{
	unsigned i;

	for (i = 0; i < server->max_leases; i++)
		if (server->leases[i].lease_nip == nip)
			return &server->leases[i];

	return NULL;
}

/* Find a new usable (we think) address */
static uint32_t find_free_or_expired_nip(struct udhcpd_server *server)
{
	uint32_t addr;
	struct dyn_lease *oldest_lease = NULL;

	addr = server->start_ip;
	do {
		uint32_t nip;
		struct dyn_lease *lease;

		/* ie, 192.168.55.0 */
		if ((addr & 0xff) == 0)
			goto next_addr;
		/* ie, 192.168.55.255 */
		if ((addr & 0xff) == 0xff)
			goto next_addr;
		nip = htonl(addr);
		/* skip our own address */
		if (nip == server->pcb->local_ip.addr)
			goto next_addr;

		lease = find_lease_by_nip(server, nip);
		if (!lease) {
			return nip;
		} else {
			if (!oldest_lease || lease->expires < oldest_lease->expires)
				oldest_lease = lease;
		}

 next_addr:
		addr++;
	} while (addr != server->end_ip + 1);

	if (oldest_lease
	 && is_expired_lease(oldest_lease)
	) {
		return oldest_lease->lease_nip;
	}

	return 0;
}

/* Send a packet to a specific mac address and ip address by creating our own ip packet */
static void send_packet_to_client(struct udhcpd_server *server, struct dhcp_packet *dhcp_pkt, int force_broadcast)
{
	const uint8_t *chaddr;
	uint32_t ciaddr;

	if (force_broadcast
	 || (dhcp_pkt->flags & htons(BROADCAST_FLAG))
	 || dhcp_pkt->ciaddr == 0
	) {
		ciaddr = INADDR_BROADCAST;
		chaddr = MAC_BCAST_ADDR;
	} else {
		ciaddr = dhcp_pkt->ciaddr;
		chaddr = dhcp_pkt->chaddr;
	}

	udhcp_send_raw_packet(dhcp_pkt,
		/*src*/ server->pcb,
		/*dst*/ ciaddr, server->port + 1, chaddr);
}

/* Send a packet to gateway_nip using the kernel ip stack */
static void send_packet_to_relay(struct udhcpd_server *server, struct dhcp_packet *dhcp_pkt)
{
	/* forwarding packet to relay */
	udhcp_send_kernel_packet(dhcp_pkt, server->pcb, dhcp_pkt->gateway_nip, server->port);
}

static void send_packet(struct udhcpd_server *server, struct dhcp_packet *dhcp_pkt, int force_broadcast)
{
	if (dhcp_pkt->gateway_nip)
		send_packet_to_relay(server, dhcp_pkt);
	else
		send_packet_to_client(server, dhcp_pkt, force_broadcast);
}

static void init_packet(struct udhcpd_server *server, struct dhcp_packet *packet, struct dhcp_packet *oldpacket, char type)
{
	/* Sets op, htype, hlen, cookie fields
	 * and adds DHCP_MESSAGE_TYPE option */
	udhcp_init_header(packet, type);

	packet->xid = oldpacket->xid;
	memcpy(packet->chaddr, oldpacket->chaddr, sizeof(oldpacket->chaddr));
	packet->flags = oldpacket->flags;
	packet->gateway_nip = oldpacket->gateway_nip;
	packet->ciaddr = oldpacket->ciaddr;
	udhcp_add_simple_option(packet, DHCP_SERVER_ID, server->pcb->local_ip.addr);
}

/* Fill options field, siaddr_nip, and sname and boot_file fields.
 * TODO: teach this code to use overload option.
 */
static void add_server_options(struct udhcpd_server *server, struct dhcp_packet *packet)
{
	struct option_set *curr = server->options;

	while (curr) {
		if (curr->data[OPT_CODE] != DHCP_LEASE_TIME)
			udhcp_add_binary_option(packet, curr->data);
		curr = curr->next;
	}

	packet->siaddr_nip = server->siaddr_nip;

	if (server->sname)
		strncpy((char*)packet->sname, server->sname, sizeof(packet->sname) - 1);
	if (server->boot_file)
		strncpy((char*)packet->file, server->boot_file, sizeof(packet->file) - 1);
}

static uint32_t select_lease_time(struct udhcpd_server *server, struct dhcp_packet *packet)
{
	uint32_t lease_time_sec = server->max_lease_sec;
	uint8_t *lease_time_opt = udhcp_get_option(packet, DHCP_LEASE_TIME);
	if (lease_time_opt) {
		lease_time_sec = ntohl(*(uint32_t *)lease_time_opt);
		if (lease_time_sec > server->max_lease_sec)
			lease_time_sec = server->max_lease_sec;
		if (lease_time_sec < server->min_lease_sec)
			lease_time_sec = server->min_lease_sec;
	}
	return lease_time_sec;
}

/* We got a DHCP DISCOVER. Send an OFFER. */
/* NOINLINE: limit stack usage in caller */
static void send_offer(struct udhcpd_server *server,
		struct dhcp_packet *oldpacket,
		struct dyn_lease *lease,
		uint8_t *requested_ip_opt)
{
	struct dhcp_packet packet;
	uint32_t lease_time_sec;
	uint32_t req_nip;

	init_packet(server, &packet, oldpacket, DHCPOFFER);

	if (lease) {
		/* We have a dynamic lease for client's chaddr.
		 * Reuse its IP (even if lease is expired).
		 * Note that we ignore requested IP in this case.
		 */
		packet.yiaddr = lease->lease_nip;
	}
	/* Or: if client has requested an IP */
	else if (requested_ip_opt != NULL
	 /* (read IP) */
	 && (req_nip = *(uint32_t *)requested_ip_opt)
	 /* and the IP is in the lease range */
	 && ntohl(req_nip) >= server->start_ip
	 && ntohl(req_nip) <= server->end_ip
	 /* and */
	 && (  !(lease = find_lease_by_nip(server, req_nip)) /* is not already taken */
	    || is_expired_lease(lease) /* or is taken, but expired */
	    )
	) {
		packet.yiaddr = req_nip;
	}
	else {
		/* Otherwise, find a free IP */
		packet.yiaddr = find_free_or_expired_nip(server);
	}

	if (!packet.yiaddr) {
		/* no free IP addresses. OFFER abandoned */
		return;
	}
	/* Reserve the IP for a short time hoping to get DHCPREQUEST soon */
	lease = add_lease(server, packet.chaddr, packet.yiaddr, server->offer_time);
	if (!lease) {
		/* no free IP addresses. OFFER abandoned */
		return;
	}

	lease_time_sec = select_lease_time(server, oldpacket);
	udhcp_add_simple_option(&packet, DHCP_LEASE_TIME, htonl(lease_time_sec));
	add_server_options(server, &packet);

	/* send_packet emits error message itself if it detects failure */
	send_packet(server, &packet, /*force_bcast:*/ 0);
}

static void send_NAK(struct udhcpd_server *server, struct dhcp_packet *oldpacket)
{
	struct dhcp_packet packet;

	init_packet(server, &packet, oldpacket, DHCPNAK);

	send_packet(server, &packet, /*force_bcast:*/ 1);
}

static void send_ACK(struct udhcpd_server *server, struct dhcp_packet *oldpacket, uint32_t yiaddr)
{
	struct dhcp_packet packet;
	uint32_t lease_time_sec;

	init_packet(server, &packet, oldpacket, DHCPACK);
	packet.yiaddr = yiaddr;

	lease_time_sec = select_lease_time(server, oldpacket);
	udhcp_add_simple_option(&packet, DHCP_LEASE_TIME, htonl(lease_time_sec));

	add_server_options(server, &packet);

	send_packet(server, &packet, /*force_bcast:*/ 0);

	add_lease(server, packet.chaddr, packet.yiaddr, lease_time_sec);
}

static void send_inform(struct udhcpd_server *server, struct dhcp_packet *oldpacket)
{
	struct dhcp_packet packet;

	/* "If a client has obtained a network address through some other means
	 * (e.g., manual configuration), it may use a DHCPINFORM request message
	 * to obtain other local configuration parameters.  Servers receiving a
	 * DHCPINFORM message construct a DHCPACK message with any local
	 * configuration parameters appropriate for the client without:
	 * allocating a new address, checking for an existing binding, filling
	 * in 'yiaddr' or including lease time parameters.  The servers SHOULD
	 * unicast the DHCPACK reply to the address given in the 'ciaddr' field
	 * of the DHCPINFORM message.
	 * ...
	 * The server responds to a DHCPINFORM message by sending a DHCPACK
	 * message directly to the address given in the 'ciaddr' field
	 * of the DHCPINFORM message.  The server MUST NOT send a lease
	 * expiration time to the client and SHOULD NOT fill in 'yiaddr'."
	 */
//TODO: do a few sanity checks: is ciaddr set?
//Better yet: is ciaddr == IP source addr?
	init_packet(server, &packet, oldpacket, DHCPACK);
	add_server_options(server, &packet);

	send_packet(server, &packet, /*force_bcast:*/ 0);
}

static void udhcpd_udp_recv(void *priv, struct udp_pcb *pcb, struct pbuf *p,
							const ip_addr_t *addr, u16_t port)
{
	struct udhcpd_server *server = priv;
	struct dhcp_packet packet;
	uint8_t *state;
	int bytes;
	uint8_t *server_id_opt;
	uint8_t *requested_ip_opt;
	uint32_t requested_nip = requested_nip; /* for compiler */
	struct dyn_lease *lease;

	bytes = udhcp_recv_kernel_packet(&packet, p);
	pbuf_free(p);
	if (bytes < 0)
		return;

	LWIP_DEBUGF(UDHCP_DEBUG, ("%s: read %d DHCP packet\n", __func__, bytes));

	if (packet.hlen != 6) {
		/* MAC length != 6, ignoring packet */
		return;
	}

	if (packet.op != BOOTREQUEST) {
		/* not a REQUEST, ignoring packet */
		return;
	}

	state = udhcp_get_option(&packet, DHCP_MESSAGE_TYPE);
	if (state == NULL || state[0] < DHCP_MINTYPE || state[0] > DHCP_MAXTYPE) {
		/* no or bad message type option, ignoring packet */
		return;
	}

	/* Get SERVER_ID if present */
	server_id_opt = udhcp_get_option(&packet, DHCP_SERVER_ID);
	if (server_id_opt) {
		uint32_t server_id_network_order;
		server_id_network_order = *(uint32_t *)server_id_opt;
		if (server_id_network_order != server->pcb->local_ip.addr) {
			/* client talks to somebody else */
			/* server ID doesn't match, ignoring */
			return;
		}
	}

	/* Look for a static/dynamic lease */
	lease = find_lease_by_mac(server, packet.chaddr);

	/* Get REQUESTED_IP if present */
	requested_ip_opt = udhcp_get_option(&packet, DHCP_REQUESTED_IP);
	if (requested_ip_opt)
		requested_nip = *(uint32_t *)requested_ip_opt;

	switch (state[0]) {
	case DHCPDISCOVER:
		send_offer(server, &packet, lease, requested_ip_opt);
		break;

	case DHCPREQUEST:
/* RFC 2131:

o DHCPREQUEST generated during SELECTING state:

Client inserts the address of the selected server in 'server
identifier', 'ciaddr' MUST be zero, 'requested IP address' MUST be
filled in with the yiaddr value from the chosen DHCPOFFER.

Note that the client may choose to collect several DHCPOFFER
messages and select the "best" offer.  The client indicates its
selection by identifying the offering server in the DHCPREQUEST
message.  If the client receives no acceptable offers, the client
may choose to try another DHCPDISCOVER message.  Therefore, the
servers may not receive a specific DHCPREQUEST from which they can
decide whether or not the client has accepted the offer.

o DHCPREQUEST generated during INIT-REBOOT state:

'server identifier' MUST NOT be filled in, 'requested IP address'
option MUST be filled in with client's notion of its previously
assigned address. 'ciaddr' MUST be zero. The client is seeking to
verify a previously allocated, cached configuration. Server SHOULD
send a DHCPNAK message to the client if the 'requested IP address'
is incorrect, or is on the wrong network.

Determining whether a client in the INIT-REBOOT state is on the
correct network is done by examining the contents of 'giaddr', the
'requested IP address' option, and a database lookup. If the DHCP
server detects that the client is on the wrong net (i.e., the
result of applying the local subnet mask or remote subnet mask (if
'giaddr' is not zero) to 'requested IP address' option value
doesn't match reality), then the server SHOULD send a DHCPNAK
message to the client.

If the network is correct, then the DHCP server should check if
the client's notion of its IP address is correct. If not, then the
server SHOULD send a DHCPNAK message to the client. If the DHCP
server has no record of this client, then it MUST remain silent,
and MAY output a warning to the network administrator. This
behavior is necessary for peaceful coexistence of non-
communicating DHCP servers on the same wire.

If 'giaddr' is 0x0 in the DHCPREQUEST message, the client is on
the same subnet as the server.  The server MUST broadcast the
DHCPNAK message to the 0xffffffff broadcast address because the
client may not have a correct network address or subnet mask, and
the client may not be answering ARP requests.

If 'giaddr' is set in the DHCPREQUEST message, the client is on a
different subnet.  The server MUST set the broadcast bit in the
DHCPNAK, so that the relay agent will broadcast the DHCPNAK to the
client, because the client may not have a correct network address
or subnet mask, and the client may not be answering ARP requests.

o DHCPREQUEST generated during RENEWING state:

'server identifier' MUST NOT be filled in, 'requested IP address'
option MUST NOT be filled in, 'ciaddr' MUST be filled in with
client's IP address. In this situation, the client is completely
configured, and is trying to extend its lease. This message will
be unicast, so no relay agents will be involved in its
transmission.  Because 'giaddr' is therefore not filled in, the
DHCP server will trust the value in 'ciaddr', and use it when
replying to the client.

A client MAY choose to renew or extend its lease prior to T1.  The
server may choose not to extend the lease (as a policy decision by
the network administrator), but should return a DHCPACK message
regardless.

o DHCPREQUEST generated during REBINDING state:

'server identifier' MUST NOT be filled in, 'requested IP address'
option MUST NOT be filled in, 'ciaddr' MUST be filled in with
client's IP address. In this situation, the client is completely
configured, and is trying to extend its lease. This message MUST
be broadcast to the 0xffffffff IP broadcast address.  The DHCP
server SHOULD check 'ciaddr' for correctness before replying to
the DHCPREQUEST.

The DHCPREQUEST from a REBINDING client is intended to accommodate
sites that have multiple DHCP servers and a mechanism for
maintaining consistency among leases managed by multiple servers.
A DHCP server MAY extend a client's lease only if it has local
administrative authority to do so.
*/
		if (!requested_ip_opt) {
			requested_nip = packet.ciaddr;
			if (requested_nip == 0) {
				/* no requested IP and no ciaddr, ignoring */
				break;
			}
		}
		if (lease && requested_nip == lease->lease_nip) {
			/* client requested or configured IP matches the lease.
			 * ACK it, and bump lease expiration time. */
			send_ACK(server, &packet, lease->lease_nip);
			break;
		}
		/* No lease for this MAC, or lease IP != requested IP */

		if (server_id_opt    /* client is in SELECTING state */
		 || requested_ip_opt /* client is in INIT-REBOOT state */
		) {
			/* "No, we don't have this IP for you" */
			send_NAK(server, &packet);
		} /* else: client is in RENEWING or REBINDING, do not answer */

		break;

	case DHCPDECLINE:
		/* RFC 2131:
		 * "If the server receives a DHCPDECLINE message,
		 * the client has discovered through some other means
		 * that the suggested network address is already
		 * in use. The server MUST mark the network address
		 * as not available and SHOULD notify the local
		 * sysadmin of a possible configuration problem."
		 *
		 * SERVER_ID must be present,
		 * REQUESTED_IP must be present,
		 * chaddr must be filled in,
		 * ciaddr must be 0 (we do not check this)
		 */
		if (server_id_opt
		 && requested_ip_opt
		 && lease  /* chaddr matches this lease */
		 && requested_nip == lease->lease_nip
		) {
			memset(lease->lease_mac, 0, sizeof(lease->lease_mac));
			lease->expires = time(NULL) + server->decline_time;
		}
		break;

	case DHCPRELEASE:
		/* "Upon receipt of a DHCPRELEASE message, the server
		 * marks the network address as not allocated."
		 *
		 * SERVER_ID must be present,
		 * REQUESTED_IP must not be present (we do not check this),
		 * chaddr must be filled in,
		 * ciaddr must be filled in
		 */
		if (server_id_opt
		 && lease  /* chaddr matches this lease */
		 && packet.ciaddr == lease->lease_nip
		) {
			lease->expires = time(NULL);
		}
		break;

	case DHCPINFORM:
		send_inform(server, &packet);
		break;
	}
}

struct udhcpd_server *udhcpd_init(const struct netif *netif, uint16_t port)
{
	int retval;
	unsigned num_ips;
	struct udhcpd_server *server;

	server = malloc(sizeof(*server));
	memset(server, 0, sizeof(*server));

	server->port = port;
	server->max_leases = 1023;
	server->decline_time = 3600;
	server->offer_time = 60;
	server->min_lease_sec = 60;

	/* started */
	server->max_lease_sec = DEFAULT_LEASE_TIME;
	server->start_ip = ntohl(netif->ip_addr.addr & netif->netmask.addr);
	server->end_ip = server->start_ip + ntohl(~netif->netmask.addr);

	/* Sanity check */
	num_ips = server->end_ip - server->start_ip + 1;
	if (server->max_leases > num_ips) {
		/* max_leases is too big */
		server->max_leases = num_ips;
	}

	server->pcb = udp_new();
	if (!server->pcb) {
		free(server);
		return NULL;
	}

	retval = udp_bind(server->pcb, &netif->ip_addr, server->port);
	if (retval < 0) {
		udp_remove(server->pcb);
		free(server);
		return NULL;
	}

	server->leases = malloc(server->max_leases * sizeof(server->leases[0]));
	memset(server->leases, 0, server->max_leases * sizeof(server->leases[0]));

	udp_bind_netif(server->pcb, netif);
	udp_recv(server->pcb, udhcpd_udp_recv, server);

	return server;
}

