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

gint add_tcpv4trace(struct in_addr, struct in_addr, uint16_t, uint16_t, uint8_t);
gint add_udpv4trace(struct in_addr, struct in_addr, uint16_t, uint16_t, uint8_t);
gint add_icmpv4trace(struct in_addr, struct in_addr, uint8_t, uint8_t, uint8_t);
gint add_tcpv6trace(struct in6_addr, struct in6_addr, uint16_t, uint16_t, uint8_t);
gint add_udpv6trace(struct in6_addr, struct in6_addr, uint16_t, uint16_t, uint8_t);
gint add_icmpv6trace(struct in6_addr, struct in6_addr, uint8_t, uint8_t, uint8_t);

void nfnetlink_start(void);
gint iptables_cleanup(void);
gint iptables_leftovers(void);

#endif // IPTABLES_H_
