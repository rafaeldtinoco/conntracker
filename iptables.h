/*
 * (C) 2021 by Rafael David Tinoco <rafael.tinoco@ibm.com>
 * (C) 2021 by Rafael David Tinoco <rafaeldtinoco@ubuntu.com>
 */

#ifndef IPTABLES_H_
#define IPTABLES_H_

#include "general.h"

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>

gint add_conntrack(void);
gint del_conntrack(void);

gint start_tcpv4trace(struct in_addr, struct in_addr, u16, u16);
gint start_udpv4trace(struct in_addr, struct in_addr, u16, u16);
gint start_icmpv4trace(struct in_addr, struct in_addr, u8, u8);
gint start_tcpv6trace(struct in6_addr, struct in6_addr, u16, u16);
gint start_udpv6trace(struct in6_addr, struct in6_addr, u16, u16);
gint start_icmpv6trace(struct in6_addr, struct in6_addr, u8, u8);

void nfnetlink_start(void);
gint iptables_cleanup(void);
gint iptables_leftovers(void);
gint iptables_init(void);

#endif // IPTABLES_H_
