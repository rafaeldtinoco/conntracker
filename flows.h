/*
 * (C) 2021 by Rafael David Tinoco <rafael.tinoco@ibm.com>
 * (C) 2021 by Rafael David Tinoco <rafaeldtinoco@ubuntu.com>
 */

#ifndef FLOWS_H_
#define FLOWS_H_

#include "general.h"
#include "footprint.h"


// base

struct ipv4base {
	struct in_addr src;
	struct in_addr dst;
};

struct ipv6base {
	struct in6_addr src;
	struct in6_addr dst;
};

struct portbase {
	u16 src;
	u16 dst;
};

struct icmpbase {
	u8 type;
	u8 code;
};

// flows

struct tcpv4flow {
	struct ipv4base addrs;
	struct portbase base;
	struct footprints foots;
};

struct udpv4flow {
	struct ipv4base addrs;
	struct portbase base;
	struct footprints foots;
};

struct icmpv4flow {
	struct ipv4base addrs;
	struct icmpbase base;
	struct footprints foots;
};

// IPv6 netfilter flows

struct tcpv6flow {
	struct ipv6base addrs;
	struct portbase base;
	struct footprints foots;
};

struct udpv6flow {
	struct ipv6base addrs;
	struct portbase base;
	struct footprints foots;
};

struct icmpv6flow {
	struct ipv6base addrs;
	struct icmpbase base;
	struct footprints foots;
};

// prototypes

gchar *ipv4_str(struct in_addr *);
gchar *ipv6_str(struct in6_addr *);

void invert_tcpv4flow(struct tcpv4flow *, struct tcpv4flow *);

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

gint add_tcpv4flow(struct in_addr, struct in_addr, u16, u16);
gint add_udpv4flow(struct in_addr, struct in_addr, u16, u16);
gint add_icmpv4flow(struct in_addr, struct in_addr, u8, u8);
gint add_tcpv6flow(struct in6_addr, struct in6_addr, u16, u16);
gint add_udpv6flow(struct in6_addr, struct in6_addr, u16, u16);
gint add_icmpv6flow(struct in6_addr, struct in6_addr, u8, u8);

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

void cleanflow_tcpv4(gpointer);
void cleanflow_udpv4(gpointer);
void cleanflow_icmpv4(gpointer);
void cleanflow_tcpv6(gpointer);
void cleanflow_udpv6(gpointer);
void cleanflow_icmpv6(gpointer);

void alloc_flows(void);
void cleanflow(gpointer);
void out_all(void);
void free_flows(void);

#endif /* FLOWS_H_ */
