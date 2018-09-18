/* vi: set sw=4 ts=4: */
/*
 * Packet ops
 *
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 *
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
#include "udhcp_common.h"
#include "dhcpd.h"

#include <string.h>
#include <stddef.h>
#include <arpa/inet.h>

#include <lwip/pbuf.h>
#include <lwip/netif.h>
#include <lwip/inet_chksum.h>
#include <lwip/udp.h>

#include <netif/ethernet.h>

void udhcp_init_header(struct dhcp_packet *packet, char type)
{
	memset(packet, 0, sizeof(*packet));
	packet->op = BOOTREQUEST; /* if client to a server */
	switch (type) {
	case DHCPOFFER:
	case DHCPACK:
	case DHCPNAK:
		packet->op = BOOTREPLY; /* if server to client */
	}
	packet->htype = 1; /* ethernet */
	packet->hlen = 6;
	packet->cookie = htonl(DHCP_MAGIC);
	if (DHCP_END != 0)
		packet->options[0] = DHCP_END;
	udhcp_add_simple_option(packet, DHCP_MESSAGE_TYPE, type);
}


/* Read a packet from socket fd, return -1 on read error, -2 on packet error */
int udhcp_recv_kernel_packet(struct dhcp_packet *packet, struct pbuf *p)
{
	int bytes;

	memset(packet, 0, sizeof(*packet));
	bytes = pbuf_copy_partial(p, packet, sizeof(*packet), 0);
	if (bytes < 0) {
		/* packet read error, ignoring */
		return bytes; /* returns -1 */
	}

	if (bytes < offsetof(struct dhcp_packet, options)
	 || packet->cookie != htonl(DHCP_MAGIC)
	) {
		/* packet with bad magic, ignoring */
		return -2;
	}

	return bytes;
}

/* Construct a ip/udp header for a packet, send packet */
int udhcp_send_raw_packet(struct dhcp_packet *dhcp_pkt,
		struct udp_pcb *pcb,
		uint32_t dest_nip, int dest_port, const uint8_t *dest_arp)
{
	struct ip_udp_dhcp_packet packet;
	struct netif *netif;
	struct pbuf *p;
	unsigned padding;
	int result = -1;
	struct eth_addr eth_src;
	struct eth_addr eth_dest;

	netif = netif_get_by_index(pcb->netif_idx);
	if (!netif)
		return -1;

	memset(&packet, 0, offsetof(struct ip_udp_dhcp_packet, data));
	packet.data = *dhcp_pkt; /* struct copy */

	/* We were sending full-sized DHCP packets (zero padded),
	 * but some badly configured servers were seen dropping them.
	 * Apparently they drop all DHCP packets >576 *ethernet* octets big,
	 * whereas they may only drop packets >576 *IP* octets big
	 * (which for typical Ethernet II means 590 octets: 6+6+2 + 576).
	 *
	 * In order to work with those buggy servers,
	 * we truncate packets after end option byte.
	 *
	 * However, RFC 1542 says "The IP Total Length and UDP Length
	 * must be large enough to contain the minimal BOOTP header of 300 octets".
	 * Thus, we retain enough padding to not go below 300 BOOTP bytes.
	 * Some devices have filters which drop DHCP packets shorter than that.
	 */
	padding = DHCP_OPTIONS_BUFSIZE - 1 - udhcp_end_option(packet.data.options);
	if (padding > DHCP_SIZE - 300)
		padding = DHCP_SIZE - 300;

	IPH_PROTO(&packet.ip) = IPPROTO_UDP;
	packet.ip.src.addr = pcb->local_ip.addr;
	packet.ip.dest.addr = dest_nip;
	packet.udp.src = htons(pcb->local_port);
	packet.udp.dest = htons(dest_port);
	/* size, excluding IP header: */
	packet.udp.len = htons(UDP_DHCP_SIZE - padding);
	/* for UDP checksumming, ip.len is set to UDP packet len */
	IPH_LEN(&packet.ip) = packet.udp.len;
	packet.udp.chksum = inet_chksum((uint16_t *)&packet, IP_UDP_DHCP_SIZE - padding);
	/* but for sending, it is set to IP packet len */
	IPH_LEN(&packet.ip) = htons(IP_UDP_DHCP_SIZE - padding);
	IPH_VHL_SET(&packet.ip, 4, sizeof(packet.ip) >> 2);
	IPH_TTL(&packet.ip) = 64;
	IPH_CHKSUM(&packet.ip) = inet_chksum((uint16_t *)&packet.ip, sizeof(packet.ip));

	p = pbuf_alloc(PBUF_LINK, IP_UDP_DHCP_SIZE - padding, PBUF_RAM);
	pbuf_take(p, &packet, IP_UDP_DHCP_SIZE - padding);

	memcpy(eth_src.addr, netif->hwaddr, sizeof(eth_src.addr));
	memcpy(eth_dest.addr, dest_arp, sizeof(eth_dest.addr));
	result = ethernet_output(netif, p, &eth_src, &eth_dest, ETHTYPE_IP);
	pbuf_free(p);
	return result;
}

/* Let the kernel do all the work for packet generation */
int udhcp_send_kernel_packet(struct dhcp_packet *dhcp_pkt,
		struct udp_pcb *pcb,
		uint32_t dest_nip, int dest_port)
{
	unsigned padding;
	int result;
	ip_addr_t dst_ip;
	struct pbuf *p;

	padding = DHCP_OPTIONS_BUFSIZE - 1 - udhcp_end_option(dhcp_pkt->options);
	if (padding > DHCP_SIZE - 300)
		padding = DHCP_SIZE - 300;

	p = pbuf_alloc(PBUF_TRANSPORT, DHCP_SIZE - padding, PBUF_RAM);
	pbuf_take(p, dhcp_pkt, DHCP_SIZE - padding);

	dst_ip.addr = dest_nip;
	result = udp_sendto(pcb, p, &dst_ip, dest_port);
	pbuf_free(p);

	return result;
}
