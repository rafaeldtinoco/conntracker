/*
 * (C) 2021 by Rafael David Tinoco <rafael.tinoco@ibm.com>
 * (C) 2021 by Rafael David Tinoco <rafaeldtinoco@ubuntu.com>
 */

#ifndef FOOTPRINT_H_
#define FOOTPRINT_H_

#include "general.h"

/* footprints */

struct footprints {
	uint8_t traced;
	uint8_t reply;
	GSequence *fp;
};

struct footprint {
	enum {
		FOOTPRINT_TABLE_RAW = 1,
		FOOTPRINT_TABLE_MANGLE = 2,
		FOOTPRINT_TABLE_NAT = 3,
		FOOTPRINT_TABLE_FILTER = 4,
		FOOTPRINT_TABLE_UNKNOWN = 255
	} table;
	enum {
		FOOTPRINT_TYPE_POLICY = 1,
		FOOTPRINT_TYPE_RULE = 2,
		FOOTPRINT_TYPE_RETURN = 3,
		FOOTPRINT_TYPE_UNKNOWN = 255
	} type;
	/*
	 * chains can be created so they are dynamic
	 * I haven looked at chain name max length
	 */
	char chain[20];
	uint32_t position;
};

gint cmp_footprint(gconstpointer, gconstpointer, gpointer);

gint add_tcpv4fp(struct in_addr, struct in_addr, uint16_t, uint16_t, uint8_t, struct footprint *);
gint add_udpv4fp(struct in_addr, struct in_addr, uint16_t, uint16_t, uint8_t, struct footprint *);
gint add_icmpv4fp(struct in_addr, struct in_addr, uint8_t, uint8_t, uint8_t, struct footprint *);
gint add_tcpv6fp(struct in6_addr, struct in6_addr, uint16_t, uint16_t, uint8_t, struct footprint *);
gint add_udpv6fp(struct in6_addr, struct in6_addr, uint16_t, uint16_t, uint8_t, struct footprint *);
gint add_icmpv6fp(struct in6_addr, struct in6_addr, uint8_t, uint8_t, uint8_t, struct footprint *);

void out_footprint(gpointer, gpointer);

void cleanfp(gpointer);

#endif /* FOOTPRINT_H_ */
