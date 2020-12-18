#ifndef FLOWS_H_
#define FLOWS_H_

#include "general.h"

extern int logfd;

struct footprint {
	uint8_t reply;
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
	char chain[20]; /* did not look for chain max name length */
	uint32_t position;
};

/* base */

struct ipv4base {
	struct in_addr src;
	struct in_addr dst;
};

struct ipv6base {
	struct in6_addr src;
	struct in6_addr dst;
};

struct portbase {
	uint16_t src;
	uint16_t dst;
};

struct icmpbase {
	uint8_t type;
	uint8_t code;
};

/* flows */

struct tcpv4flow {
	struct ipv4base addrs;
	struct portbase base;
	struct footprint foot;
};

struct udpv4flow {
	struct ipv4base addrs;
	struct portbase base;
	struct footprint foot;
};

struct icmpv4flow {
	struct ipv4base addrs;
	struct icmpbase base;
	struct footprint foot;
};

/* IPv6 netfilter flows */

struct tcpv6flow {
	struct ipv6base addrs;
	struct portbase base;
	struct footprint foot;
};

struct udpv6flow {
	struct ipv6base addrs;
	struct portbase base;
	struct footprint foot;
};

struct icmpv6flow {
	struct ipv6base addrs;
	struct icmpbase base;
	struct footprint foot;
};

/* prototypes */

gchar *ipv4_str(struct in_addr *);
gchar *ipv6_str(struct in6_addr *);

gint cmp_ipv4base(struct ipv4base, struct ipv4base);
gint cmp_portbase(struct portbase, struct portbase);
gint cmp_icmpbase(struct icmpbase, struct icmpbase);
gint cmp_ipv6base(struct ipv6base, struct ipv6base);

gint cmp_tcp4flow(struct tcpv4flow *, struct tcpv4flow *);
gint cmp_udpv4flow(struct udpv4flow *, struct udpv4flow *);
gint cmp_icmpv4flow(struct icmpv4flow *, struct icmpv4flow *);
gint cmp_tcp6flow(struct tcpv6flow *, struct tcpv6flow *);
gint cmp_udpv6flow(struct udpv6flow *, struct udpv6flow *);
gint cmp_icmpv6flow(struct icmpv6flow *, struct icmpv6flow *);

gint cmp_tcpv4flows(gconstpointer, gconstpointer, gpointer);
gint cmp_udpv4flows(gconstpointer, gconstpointer, gpointer);
gint cmp_icmpv4flows(gconstpointer, gconstpointer, gpointer);
gint cmp_tcpv6flows(gconstpointer, gconstpointer, gpointer);
gint cmp_udpv6flows(gconstpointer, gconstpointer, gpointer);
gint cmp_icmpv6flows(gconstpointer, gconstpointer, gpointer);

gint addtcpv4flow(struct in_addr, struct in_addr, uint16_t, uint16_t, uint8_t);
gint addudpv4flow(struct in_addr, struct in_addr, uint16_t, uint16_t, uint8_t);
gint addicmpv4flow(struct in_addr, struct in_addr, uint16_t, uint16_t, uint8_t);
gint addtcpv6flow(struct in6_addr, struct in6_addr, uint16_t, uint16_t, uint8_t);
gint addudpv6flow(struct in6_addr, struct in6_addr, uint16_t, uint16_t, uint8_t);
gint addicmpv6flow(struct in6_addr, struct in6_addr, uint16_t, uint16_t, uint8_t);

gint add_tcpv4flows(struct tcpv4flow *);
gint add_udpv4flows(struct udpv4flow *);
gint add_icmpv4flows(struct icmpv4flow *);
gint add_tcpv6flows(struct tcpv6flow *);
gint add_udpv6flows(struct udpv6flow *);
gint add_icmpv6flows(struct icmpv6flow *);

void out_tcpv4flows(gpointer, gpointer);
void out_udpv4flows(gpointer, gpointer);
void out_icmpv4flows(gpointer, gpointer);
void out_tcpv6flows(gpointer, gpointer);
void out_udpv6flows(gpointer, gpointer);
void out_icmpv6flows(gpointer, gpointer);

void alloc_flows(void);
void cleanflow(gpointer);
void out_all(void);
void free_flows(void);

/* add flows based on given type */

#define addflows(type)										\
gint add_##type##s(struct type *flow)								\
{												\
	struct type *temp;									\
	GSequenceIter *found, *found2;								\
												\
	temp = g_malloc0(sizeof(struct type));							\
	memcpy(temp, flow, sizeof(struct type));						\
												\
	found = g_sequence_lookup(type##s, temp, cmp_##type##s, NULL);				\
												\
	if (found == NULL) { 									\
		switch (temp->foot.reply) {							\
		case 0:										\
			temp->foot.reply = 1;							\
			found2 = g_sequence_lookup(type##s, temp, cmp_##type##s, NULL); 	\
			temp->foot.reply = 0;							\
			if (found2 == NULL) {							\
				g_sequence_insert_sorted(type##s, temp, cmp_##type##s, NULL);	\
				goto inserted;							\
			}									\
			break;									\
		case 1:										\
			temp->foot.reply = 0;							\
			found2 = g_sequence_lookup(type##s, temp, cmp_##type##s, NULL); 	\
			temp->foot.reply = 1;							\
			if (found2 != NULL) {							\
				g_sequence_remove(found2);					\
				g_sequence_insert_sorted(type##s, temp, cmp_##type##s, NULL);	\
				goto inserted;							\
			}									\
			break;									\
		}										\
	}											\
												\
	g_free(temp); 										\
												\
inserted:											\
	return SUCCESS;										\
}

/* display the flows */

#define out(arg1, arg2, ...)									\
void out_##arg1##s(gpointer data, gpointer user_data)						\
{												\
	static int times = 0;									\
	gchar *src, *dst;									\
	struct arg1 *flow = data;								\
												\
	src = arg2##_str(&flow->addrs.src);							\
	dst = arg2##_str(&flow->addrs.dst);							\
												\
	dprintf(logfd, __VA_ARGS__);								\
												\
	g_free(src);										\
	g_free(dst);										\
}

#endif /* FLOWS_H_ */
