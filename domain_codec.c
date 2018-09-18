/* vi: set sw=4 ts=4: */
/*
 * RFC1035 domain compression routines (C) 2007 Gabriel Somlo <somlo at cmu.edu>
 *
 * Loosely based on the isc-dhcpd implementation by dhankins@isc.org
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define NS_MAXCDNAME  255	/* max compressed domain name length */
#define NS_MAXLABEL    63	/* max label length */
#define NS_CMPRSFLGS 0xc0	/* name compression pointer flag */

/* Convert a domain name (src) from human-readable "foo.blah.com" format into
 * RFC1035 encoding "\003foo\004blah\003com\000". Return allocated string, or
 * NULL if an error occurs.
 */
static uint8_t *convert_dname(const char *src)
{
	uint8_t c, *res, *lenptr, *dst;
	int len;

	res = malloc(strlen(src) + 2);
	dst = lenptr = res;
	dst++;

	for (;;) {
		c = (uint8_t)*src++;
		if (c == '.' || c == '\0') {  /* end of label */
			len = dst - lenptr - 1;
			/* label too long, too short, or two '.'s in a row? abort */
			if (len > NS_MAXLABEL || len == 0 || (c == '.' && *src == '.')) {
				free(res);
				return NULL;
			}
			*lenptr = len;
			if (c == '\0' || *src == '\0')	/* "" or ".": end of src */
				break;
			lenptr = dst++;
			continue;
		}
		if (c >= 'A' && c <= 'Z')  /* uppercase? convert to lower */
			c += ('a' - 'A');
		*dst++ = c;
	}

	if (dst - res >= NS_MAXCDNAME) {  /* dname too long? abort */
		free(res);
		return NULL;
	}

	*dst = 0;
	return res;
}

/* Returns the offset within cstr at which dname can be found, or -1 */
static int find_offset(const uint8_t *cstr, int clen, const uint8_t *dname)
{
	const uint8_t *c, *d;
	int off;

	/* find all labels in cstr */
	off = 0;
	while (off < clen) {
		c = cstr + off;

		if ((*c & NS_CMPRSFLGS) == NS_CMPRSFLGS) {  /* pointer, skip */
			off += 2;
			continue;
		}
		if (*c) {  /* label, try matching dname */
			d = dname;
			while (1) {
				unsigned len1 = *c + 1;
				if (memcmp(c, d, len1) != 0)
					break;
				if (len1 == 1)  /* at terminating NUL - match, return offset */
					return off;
				d += len1;
				c += len1;
				if ((*c & NS_CMPRSFLGS) == NS_CMPRSFLGS)  /* pointer, jump */
					c = cstr + (((c[0] & 0x3f) << 8) | c[1]);
			}
			off += cstr[off] + 1;
			continue;
		}
		/* NUL, skip */
		off++;
	}

	return -1;
}

/* Computes string to be appended to cstr so that src would be added to
 * the compression (best case, it's a 2-byte pointer to some offset within
 * cstr; worst case, it's all of src, converted to <4>host<3>com<0> format).
 * The computed string is returned directly; its length is returned via retlen;
 * NULL and 0, respectively, are returned if an error occurs.
 */
uint8_t* dname_enc(const uint8_t *cstr, int clen, const char *src, int *retlen)
{
	uint8_t *d, *dname;
	int off;

	dname = convert_dname(src);
	if (dname == NULL) {
		*retlen = 0;
		return NULL;
	}

	d = dname;
	while (*d) {
		if (cstr) {
			off = find_offset(cstr, clen, d);
			if (off >= 0) {	/* found a match, add pointer and return */
				*d++ = NS_CMPRSFLGS | (off >> 8);
				*d = off;
				break;
			}
		}
		d += *d + 1;
	}

	*retlen = d - dname + 1;
	return dname;
}
