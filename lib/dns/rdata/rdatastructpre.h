/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#ifndef DNS_RDATASTRUCT_H
#define DNS_RDATASTRUCT_H 1

#include <isc/lang.h>
#include <isc/sockaddr.h>

#include <dns/types.h>

ISC_LANG_BEGINDECLS

typedef struct dns_rdatacommon {
	dns_rdataclass_t			rdclass;
	dns_rdatatype_t				rdtype;
	ISC_LINK(struct dns_rdatacommon)	link;
} dns_rdatacommon_t;

#define DNS_RDATACOMMON_INIT(data, rdtype, rdclass) \
	do { \
		(data)->common.rdtype = (rdtype); \
		(data)->common.rdclass = (rdclass); \
		ISC_LINK_INIT(&(data)->common, link); \
	} while (0)
