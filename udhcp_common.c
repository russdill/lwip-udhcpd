/* vi: set sw=4 ts=4: */
/*
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 *
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
#include "udhcp_common.h"

const uint8_t MAC_BCAST_ADDR[6] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

/* Supported options are easily added here.
 * See RFC2132 for more options.
 * OPTION_REQ: these options are requested by udhcpc (unless -o).
 */
const struct dhcp_optflag dhcp_optflags[] = {
	/* flags                                    code */
	{ OPTION_IP                   | OPTION_REQ, 0x01 }, /* DHCP_SUBNET        */
	{ OPTION_S32                              , 0x02 }, /* DHCP_TIME_OFFSET   */
	{ OPTION_IP | OPTION_LIST     | OPTION_REQ, 0x03 }, /* DHCP_ROUTER        */
//	{ OPTION_IP | OPTION_LIST                 , 0x04 }, /* DHCP_TIME_SERVER   */
//	{ OPTION_IP | OPTION_LIST                 , 0x05 }, /* DHCP_NAME_SERVER   */
	{ OPTION_IP | OPTION_LIST     | OPTION_REQ, 0x06 }, /* DHCP_DNS_SERVER    */
//	{ OPTION_IP | OPTION_LIST                 , 0x07 }, /* DHCP_LOG_SERVER    */
//	{ OPTION_IP | OPTION_LIST                 , 0x08 }, /* DHCP_COOKIE_SERVER */
	{ OPTION_IP | OPTION_LIST                 , 0x09 }, /* DHCP_LPR_SERVER    */
	{ OPTION_STRING_HOST          | OPTION_REQ, 0x0c }, /* DHCP_HOST_NAME     */
	{ OPTION_U16                              , 0x0d }, /* DHCP_BOOT_SIZE     */
	{ OPTION_STRING_HOST          | OPTION_REQ, 0x0f }, /* DHCP_DOMAIN_NAME   */
	{ OPTION_IP                               , 0x10 }, /* DHCP_SWAP_SERVER   */
	{ OPTION_STRING                           , 0x11 }, /* DHCP_ROOT_PATH     */
	{ OPTION_U8                               , 0x17 }, /* DHCP_IP_TTL        */
	{ OPTION_U16                              , 0x1a }, /* DHCP_MTU           */
//TODO: why do we request DHCP_BROADCAST? Can't we assume that
//in the unlikely case it is different from typical N.N.255.255,
//server would let us know anyway?
	{ OPTION_IP                   | OPTION_REQ, 0x1c }, /* DHCP_BROADCAST     */
	{ OPTION_IP_PAIR | OPTION_LIST            , 0x21 }, /* DHCP_ROUTES        */
	{ OPTION_STRING_HOST                      , 0x28 }, /* DHCP_NIS_DOMAIN    */
	{ OPTION_IP | OPTION_LIST                 , 0x29 }, /* DHCP_NIS_SERVER    */
	{ OPTION_IP | OPTION_LIST     | OPTION_REQ, 0x2a }, /* DHCP_NTP_SERVER    */
	{ OPTION_IP | OPTION_LIST                 , 0x2c }, /* DHCP_WINS_SERVER   */
	{ OPTION_U32                              , 0x33 }, /* DHCP_LEASE_TIME    */
	{ OPTION_IP                               , 0x36 }, /* DHCP_SERVER_ID     */
	{ OPTION_STRING                           , 0x38 }, /* DHCP_ERR_MESSAGE   */
//TODO: must be combined with 'sname' and 'file' handling:
	{ OPTION_STRING_HOST                      , 0x42 }, /* DHCP_TFTP_SERVER_NAME */
	{ OPTION_STRING                           , 0x43 }, /* DHCP_BOOT_FILE     */
//TODO: not a string, but a set of LASCII strings:
//	{ OPTION_STRING                           , 0x4D }, /* DHCP_USER_CLASS    */
	{ OPTION_DNS_STRING | OPTION_LIST         , 0x77 }, /* DHCP_DOMAIN_SEARCH */
	{ OPTION_SIP_SERVERS                      , 0x78 }, /* DHCP_SIP_SERVERS   */
	{ OPTION_STATIC_ROUTES | OPTION_LIST      , 0x79 }, /* DHCP_STATIC_ROUTES */
	{ OPTION_STRING                           , 0xd1 }, /* DHCP_PXE_CONF_FILE */
	{ OPTION_STRING                           , 0xd2 }, /* DHCP_PXE_PATH_PREFIX */
	{ OPTION_U32                              , 0xd3 }, /* DHCP_REBOOT_TIME   */
	{ OPTION_STATIC_ROUTES | OPTION_LIST      , 0xf9 }, /* DHCP_MS_STATIC_ROUTES */
	{ OPTION_STRING                           , 0xfc }, /* DHCP_WPAD          */

	/* Options below have no match in dhcp_option_strings[],
	 * are not passed to dhcpc scripts, and cannot be specified
	 * with "option XXX YYY" syntax in dhcpd config file.
	 * These entries are only used internally by udhcp[cd]
	 * to correctly encode options into packets.
	 */

	{ OPTION_IP                               , 0x32 }, /* DHCP_REQUESTED_IP  */
	{ OPTION_U8                               , 0x35 }, /* DHCP_MESSAGE_TYPE  */
	{ OPTION_U16                              , 0x39 }, /* DHCP_MAX_SIZE      */
//looks like these opts will work just fine even without these defs:
//	{ OPTION_STRING                           , 0x3c }, /* DHCP_VENDOR        */
//	/* not really a string: */
//	{ OPTION_STRING                           , 0x3d }, /* DHCP_CLIENT_ID     */
	{ 0, 0 } /* zeroed terminating entry */
};


/* Lengths of the option types in binary form.
 * Used by:
 * udhcp_str2optset: to determine how many bytes to allocate.
 * xmalloc_optname_optval: to estimate string length
 * from binary option length: (option[LEN] / dhcp_option_lengths[opt_type])
 * is the number of elements, multiply it by one element's string width
 * (len_of_option_as_string[opt_type]) and you know how wide string you need.
 */
const uint8_t dhcp_option_lengths[] = {
	[OPTION_IP] =      4,
	[OPTION_IP_PAIR] = 8,
//	[OPTION_BOOLEAN] = 1,
	[OPTION_STRING] =  1,  /* ignored by udhcp_str2optset */
	[OPTION_STRING_HOST] = 1,  /* ignored by udhcp_str2optset */
	[OPTION_DNS_STRING] = 1,  /* ignored by both udhcp_str2optset and xmalloc_optname_optval */
	[OPTION_SIP_SERVERS] = 1,
	[OPTION_U8] =      1,
	[OPTION_U16] =     2,
//	[OPTION_S16] =     2,
	[OPTION_U32] =     4,
	[OPTION_S32] =     4,
	/* Just like OPTION_STRING, we use minimum length here */
	[OPTION_STATIC_ROUTES] = 5,
};

/* Get an option with bounds checking (warning, result is not aligned) */
uint8_t* udhcp_get_option(struct dhcp_packet *packet, int code)
{
	uint8_t *optionptr;
	int len;
	int rem;
	int overload = 0;
	enum {
		FILE_FIELD101  = FILE_FIELD  * 0x101,
		SNAME_FIELD101 = SNAME_FIELD * 0x101,
	};

	/* option bytes: [code][len][data1][data2]..[dataLEN] */
	optionptr = packet->options;
	rem = sizeof(packet->options);
	while (1) {
		if (rem <= 0) {
			/* bad packet, malformed option field */
			return NULL;
		}

		/* DHCP_PADDING and DHCP_END have no [len] byte */
		if (optionptr[OPT_CODE] == DHCP_PADDING) {
			rem--;
			optionptr++;
			continue;
		}
		if (optionptr[OPT_CODE] == DHCP_END) {
			if ((overload & FILE_FIELD101) == FILE_FIELD) {
				/* can use packet->file, and didn't look at it yet */
				overload |= FILE_FIELD101; /* "we looked at it" */
				optionptr = packet->file;
				rem = sizeof(packet->file);
				continue;
			}
			if ((overload & SNAME_FIELD101) == SNAME_FIELD) {
				/* can use packet->sname, and didn't look at it yet */
				overload |= SNAME_FIELD101; /* "we looked at it" */
				optionptr = packet->sname;
				rem = sizeof(packet->sname);
				continue;
			}
			break;
		}

		if (rem <= OPT_LEN)
			/* bad packet, malformed option field */
			return NULL;

		len = 2 + optionptr[OPT_LEN];
		rem -= len;

		if (rem < 0)
			/* bad packet, malformed option field */
			return NULL;

		if (optionptr[OPT_CODE] == code) {
			return optionptr + OPT_DATA;
		}

		if (optionptr[OPT_CODE] == DHCP_OPTION_OVERLOAD) {
			if (len >= 3)
				overload |= optionptr[OPT_DATA];
			/* fall through */
		}
		optionptr += len;
	}

	/* option <code> not found */
	return NULL;
}

/* Return the position of the 'end' option (no bounds checking) */
int udhcp_end_option(uint8_t *optionptr)
{
	int i = 0;

	while (optionptr[i] != DHCP_END) {
		if (optionptr[i] != DHCP_PADDING)
			i += optionptr[i + OPT_LEN] + OPT_DATA-1;
		i++;
	}
	return i;
}

/* Add an option (supplied in binary form) to the options.
 * Option format: [code][len][data1][data2]..[dataLEN]
 */
void udhcp_add_binary_option(struct dhcp_packet *packet, uint8_t *addopt)
{
	unsigned len;
	uint8_t *optionptr = packet->options;
	unsigned end = udhcp_end_option(optionptr);

	len = OPT_DATA + addopt[OPT_LEN];
	/* end position + (option code/length + addopt length) + end option */
	if (end + len + 1 >= DHCP_OPTIONS_BUFSIZE) {
//TODO: learn how to use overflow option if we exhaust packet->options[]
		/* option did not fit into the packet */
		return;
	}
	memcpy(optionptr + end, addopt, len);
	optionptr[end + len] = DHCP_END;
}

/* Add an one to four byte option to a packet */
void udhcp_add_simple_option(struct dhcp_packet *packet, uint8_t code, uint32_t data)
{
	const struct dhcp_optflag *dh;

	for (dh = dhcp_optflags; dh->code; dh++) {
		if (dh->code == code) {
			uint8_t option[6], len;

			option[OPT_CODE] = code;
			len = dhcp_option_lengths[dh->flags & OPTION_TYPE_MASK];
			option[OPT_LEN] = len;
#if defined(__BIG_ENDIAN__)
			data <<= 8 * (4 - len);
#endif
			/* Assignment is unaligned! */
			*(uint32_t *)&option[OPT_DATA] = data;
			udhcp_add_binary_option(packet, option);
			return;
		}
	}

	/* can't add option */
}

/* Find option 'code' in opt_list */
struct option_set* udhcp_find_option(struct option_set *opt_list, uint8_t code)
{
	while (opt_list && opt_list->data[OPT_CODE] < code)
		opt_list = opt_list->next;

	if (opt_list && opt_list->data[OPT_CODE] == code)
		return opt_list;
	return NULL;
}


