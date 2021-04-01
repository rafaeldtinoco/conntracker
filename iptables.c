/*
 * (C) 2021 by Rafael David Tinoco <rafael.tinoco@ibm.com>
 * (C) 2021 by Rafael David Tinoco <rafaeldtinoco@ubuntu.com>
 */

#include "iptables.h"
#include "flows.h"
#include "discover.h"

/* seqs stored in memory */

extern GSequence *tcpv4flows;
extern GSequence *udpv4flows;
extern GSequence *icmpv4flows;
extern GSequence *tcpv6flows;
extern GSequence *udpv6flows;
extern GSequence *icmpv6flows;

extern int traceitall;

char *ipv4bin = NULL;
char *ipv6bin = NULL;

gint iptables_init(void)
{
	gint retnft = 0, retleg = 0;
	struct stat s;

	retnft = stat("/sbin/iptables-nft", &s);
	retleg = stat("/sbin/iptables-legacy", &s);

	if (retleg == 0) {

		ipv4bin = g_strdup("iptables-legacy -w");
		ipv6bin = g_strdup("ip6tables-legacy -w");

	} else {

		if (retnft == 0)
			EXITERR("iptables-nft unsupported");

		if (stat("/sbin/iptables", &s) == 0) {

			ipv4bin = g_strdup("iptables -w");
			ipv6bin = g_strdup("ip6tables -w");

		} else
			EXITERR("could not find iptables");
	}

	return 0;
}

// ----

gint oper_iptables(short quiet, char *bin, char *rule)
{
	gchar cmd[1024];

	memset(cmd, 0, 1024);

	if (quiet)
		snprintf(cmd, 1024, "%s %s 2>&1 > /dev/null 2>&1", bin, rule);
	else
		snprintf(cmd, 1024, "%s %s", bin, rule);

	return system(cmd);
}

// ----

gint iptables_cleanup_oper(short quiet, char *bin)
{
	return oper_iptables(quiet, bin, "-t raw --flush");
}

gint iptables_cleanup(void)
{
	int ret = 0;

	ret |= iptables_cleanup_oper(0, ipv4bin);
	ret |= iptables_cleanup_oper(0, ipv6bin);

	return ret;
}

// ----

gint add_conntrack_oper(short quiet, char *bin)
{
	gint ret = 0;

	oper_iptables(quiet, bin, "-t mangle -I PREROUTING 1 -m conntrack --ctdir REPLY -j NFLOG --nflog-group 0");
	oper_iptables(quiet, bin, "-t mangle -I FORWARD 1 -m conntrack --ctstate  NEW,ESTABLISHED,RELATED,UNTRACKED,INVALID,SNAT,DNAT -j NFLOG --nflog-group 0");
	oper_iptables(quiet, bin, "-t mangle -I OUTPUT 1 -m conntrack --ctdir ORIGINAL -j NFLOG --nflog-group 0");

	if (traceitall) {
		oper_iptables(quiet, bin, "-t raw -A OUTPUT -j TRACE");
		oper_iptables(quiet, bin, "-t raw -A PREROUTING -j TRACE");
	}

	return ret;
}

gint add_conntrack(void)
{
	gint ret = 0;

	ret |= add_conntrack_oper(0, ipv4bin);
	ret |= add_conntrack_oper(0, ipv6bin);

	return ret;
}

gint del_conntrack_oper(short quiet, char *bin)
{
	gint ret = 0;

	oper_iptables(quiet, bin, "-t mangle -D PREROUTING -m conntrack --ctdir REPLY -j NFLOG --nflog-group 0");
	oper_iptables(quiet, bin, "-t mangle -D FORWARD -m conntrack --ctstate  NEW,ESTABLISHED,RELATED,UNTRACKED,INVALID,SNAT,DNAT -j NFLOG --nflog-group 0");
	oper_iptables(quiet, bin, "-t mangle -D OUTPUT -m conntrack --ctdir ORIGINAL -j NFLOG --nflog-group 0");

	if (traceitall) {
		oper_iptables(quiet, bin, "-t raw -D OUTPUT -j TRACE");
		oper_iptables(quiet, bin, "-t raw -D PREROUTING -j TRACE");
	}

	return ret;
}

gint del_conntrack(void)
{
	gint ret = 0;

	ret |= del_conntrack_oper(0, ipv4bin);
	ret |= del_conntrack_oper(0, ipv6bin);

	return ret;
}

// ----

gint oper_trace(gchar *bin, gchar *mid, gchar *proto, gchar *src, gchar *dst, uint16_t dport)
{
	gchar cmd[1024];

	memset(cmd, 0, 1024);

	if (dport != 0) {
		snprintf(cmd, 1024, "%s %s -t raw -p %s -s %s -d %s --dport %u -j TRACE",
			bin,
			mid,
			proto,
			src,
			dst,
			dport);
	} else {

		snprintf(cmd, 1024, "%s %s -t raw -p %s -s %s -d %s -j TRACE",
			bin,
			mid,
			proto,
			src,
			dst);
	}

	return system(cmd);
}

gint oper_trace_tcpv4flow(gchar *bin, gchar *mid, struct tcpv4flow *flow)
{
	gint ret = 0;

	gchar *src = ipv4_str(&flow->addrs.src);
	gchar *dst = ipv4_str(&flow->addrs.dst);
	uint16_t dport = ntohs(flow->base.dst);

	ret |= oper_trace(ipv4bin, mid, "tcp", src, dst, dport);

	g_free(src);
	g_free(dst);

	return ret;
}

gint oper_trace_udpv4flow(gchar *bin, gchar *mid, struct udpv4flow *flow)
{
	gint ret = 0;

	gchar *src = ipv4_str(&flow->addrs.src);
	gchar *dst = ipv4_str(&flow->addrs.dst);
	uint16_t dport = ntohs(flow->base.dst);

	ret |= oper_trace(ipv4bin, mid, "udp", src, dst, dport);

	g_free(src);
	g_free(dst);

	return ret;
}

gint oper_trace_icmpv4flow(gchar *bin, gchar *mid, struct icmpv4flow *flow)
{
	gint ret = 0;

	gchar *src = ipv4_str(&flow->addrs.src);
	gchar *dst = ipv4_str(&flow->addrs.dst);

	ret |= oper_trace(ipv4bin, mid, "icmp", src, dst, 0);

	g_free(src);
	g_free(dst);

	return ret;
}

gint oper_trace_tcpv6flow(gchar *bin, gchar *mid, struct tcpv6flow *flow)
{
	gint ret = 0;

	gchar *src = ipv6_str(&flow->addrs.src);
	gchar *dst = ipv6_str(&flow->addrs.dst);
	uint16_t dport = ntohs(flow->base.dst);

	ret |= oper_trace(ipv6bin, mid, "tcp", src, dst, dport);

	g_free(src);
	g_free(dst);

	return ret;
}

gint oper_trace_udpv6flow(gchar *bin, gchar *mid, struct udpv6flow *flow)
{
	gint ret = 0;

	gchar *src = ipv6_str(&flow->addrs.src);
	gchar *dst = ipv6_str(&flow->addrs.dst);
	uint16_t dport = ntohs(flow->base.dst);

	ret |= oper_trace(ipv6bin, mid, "udp", src, dst, dport);

	g_free(src);
	g_free(dst);

	return ret;
}

gint oper_trace_icmpv6flow(gchar *bin, gchar *mid, struct icmpv6flow *flow)
{
	gint ret = 0;

	gchar *src = ipv6_str(&flow->addrs.src);
	gchar *dst = ipv6_str(&flow->addrs.dst);

	ret |= oper_trace(ipv6bin, mid, "icmpv6", src, dst, 0);

	g_free(src);
	g_free(dst);

	return ret;
}

// ----

gint add_trace_tcpv4flow(struct tcpv4flow *flow)
{
	gint ret = 0;

	ret |= oper_trace_tcpv4flow(ipv4bin, "-A OUTPUT", flow);
	ret |= oper_trace_tcpv4flow(ipv4bin, "-A PREROUTING", flow);

	return ret;
}

gint add_trace_udpv4flow(struct udpv4flow *flow)
{
	gint ret = 0;

	ret |= oper_trace_udpv4flow(ipv4bin, "-A OUTPUT", flow);
	ret |= oper_trace_udpv4flow(ipv4bin, "-A PREROUTING", flow);

	return ret;
}

gint add_trace_icmpv4flow(struct icmpv4flow *flow)
{
	gint ret = 0;

	ret |= oper_trace_icmpv4flow(ipv4bin, "-A OUTPUT", flow);
	ret |= oper_trace_icmpv4flow(ipv4bin, "-A PREROUTING", flow);

	return ret;
}

gint add_trace_tcpv6flow(struct tcpv6flow *flow)
{
	gint ret = 0;

	ret |= oper_trace_tcpv6flow(ipv6bin, "-A OUTPUT", flow);
	ret |= oper_trace_tcpv6flow(ipv6bin, "-A PREROUTING", flow);

	return ret;
}

gint add_trace_udpv6flow(struct udpv6flow *flow)
{
	gint ret = 0;

	ret |= oper_trace_udpv6flow(ipv6bin, "-A OUTPUT", flow);
	ret |= oper_trace_udpv6flow(ipv6bin, "-A PREROUTING", flow);

	return ret;
}

gint add_trace_icmpv6flow(struct icmpv6flow *flow)
{
	gint ret = 0;

	ret |= oper_trace_icmpv6flow(ipv6bin, "-A OUTPUT", flow);
	ret |= oper_trace_icmpv6flow(ipv6bin, "-A PREROUTING", flow);

	return ret;
}

// ----

gint del_trace_tcpv4flow(struct tcpv4flow *flow)
{
	gint ret = 0;

	ret |= oper_trace_tcpv4flow(ipv4bin, "-D OUTPUT", flow);
	ret |= oper_trace_tcpv4flow(ipv4bin, "-D PREROUTING", flow);

	return ret;
}

gint del_trace_udpv4flow(struct udpv4flow *flow)
{
	gint ret = 0;

	ret |= oper_trace_udpv4flow(ipv4bin, "-D OUTPUT", flow);
	ret |= oper_trace_udpv4flow(ipv4bin, "-D PREROUTING", flow);

	return ret;
}

gint del_trace_icmpv4flow(struct icmpv4flow *flow)
{
	gint ret = 0;

	ret |= oper_trace_icmpv4flow(ipv4bin, "-D OUTPUT", flow);
	ret |= oper_trace_icmpv4flow(ipv4bin, "-D PREROUTING", flow);

	return ret;
}

gint del_trace_tcpv6flow(struct tcpv6flow *flow)
{
	gint ret = 0;

	ret |= oper_trace_tcpv6flow(ipv6bin, "-D OUTPUT", flow);
	ret |= oper_trace_tcpv6flow(ipv6bin, "-D PREROUTING", flow);

	return ret;
}

gint del_trace_udpv6flow(struct udpv6flow *flow)
{
	gint ret = 0;

	ret |= oper_trace_udpv6flow(ipv6bin, "-D OUTPUT", flow);
	ret |= oper_trace_udpv6flow(ipv6bin, "-D PREROUTING", flow);

	return ret;
}

gint del_trace_icmpv6flow(struct icmpv6flow *flow)
{
	gint ret = 0;

	ret |= oper_trace_icmpv6flow(ipv6bin, "-D OUTPUT", flow);
	ret |= oper_trace_icmpv6flow(ipv6bin, "-D PREROUTING", flow);

	return ret;
}

// ----

gint del_trace_tcpv4flow_wrap(gpointer ptr)
{
	struct tcpv4flow *flow = ptr;

	del_trace_tcpv4flow(flow);

	return FALSE; // FALSE: one time exec, disable future calls
}

gint del_trace_udpv4flow_wrap(gpointer ptr)
{
	struct udpv4flow *flow = ptr;

	del_trace_udpv4flow(flow);

	return FALSE; // FALSE: one time exec, disable future calls
}

gint del_trace_icmpv4flow_wrap(gpointer ptr)
{
	struct icmpv4flow *flow = ptr;

	del_trace_icmpv4flow(flow);

	return FALSE; // FALSE: one time exec, disable future calls
}

gint del_trace_tcpv6flow_wrap(gpointer ptr)
{
	struct tcpv6flow *flow = ptr;

	del_trace_tcpv6flow(flow);

	return FALSE; // FALSE: one time exec, disable future calls
}

gint del_trace_udpv6flow_wrap(gpointer ptr)
{
	struct udpv6flow *flow = ptr;

	del_trace_udpv6flow(flow);

	return FALSE; // FALSE: one time exec, disable future calls
}

gint del_trace_icmpv6flow_wrap(gpointer ptr)
{
	struct icmpv6flow *flow = ptr;

	del_trace_icmpv6flow(flow);

	return FALSE; // FALSE: one time exec, disable future calls
}

// ----

gint add_tcpv4traces(struct tcpv4flow *flow)
{
	struct tcpv4flow *ptr;
	GSequenceIter *found = NULL, *found2 = NULL;

	found = g_sequence_lookup(tcpv4flows, flow, cmp_tcpv4flows, NULL);

	if (found == NULL) {

		switch (flow->foots.reply) {
		case 0:
			/* check if confirmed flow exists. if not, we have a bug */
			flow->foots.reply = 1;
			found2 = g_sequence_lookup(tcpv4flows, flow, cmp_tcpv4flows, NULL);
			flow->foots.reply = 0;
			break;
		case 1:
			/* check if unconfirmed flow exists. if not, we have a bug */
			flow->foots.reply = 0;
			found2 = g_sequence_lookup(tcpv4flows, flow, cmp_tcpv4flows, NULL);
			flow->foots.reply = 1;
			break;
		}

		if (found2 == NULL)
			EXITERR("BUG: add_tcpv4traces");

		found = found2;
	}

	/* Update sequence entry: traced == was traced once
	 *
	 * Note: this will never be zero again as traces are enabled
	 * only once, at the flow entry creation. We don't want traces
	 * to exist forever to avoid netfilter overload.
	 */

	ptr = g_sequence_get(found);

	if (ptr->foots.traced == 1)
		return 0;

	ptr->foots.traced = 1;

	/* Here we add the netfilter trace rules that will allow ulog netfilter
	 * to receive tracing data from the kernel, telling us all the rules that
	 * affected this flow
	 */

	add_trace_tcpv4flow(ptr);

	/* Assuming that the netfilter won't change during the execution of
	 * this tool, there is no need to renew the tracing, thus no need to
	 * keep the trace rules forever. Add a timeout for the rule removal.
	 *
	 * The ulog netfilter code will only work while the trace is enabled.
	 */

	g_timeout_add_seconds(30, del_trace_tcpv4flow_wrap, ptr);

	/*
	 * Note: Discovering the task name/cmd through procfs is broken in
	 * concept as finding network inode and task responsible for it takes
	 * too long, sometimes more than the communication itself. Let's
	 * replace this by the eBPF approach.
	 *
	 * disc_app_tcpv4flow(ptr);
	 */

	return 0;
}

gint add_udpv4traces(struct udpv4flow *flow)
{
	struct udpv4flow *ptr;
	GSequenceIter *found = NULL, *found2 = NULL;

	found = g_sequence_lookup(udpv4flows, flow, cmp_udpv4flows, NULL);

	if (found == NULL) {

		switch (flow->foots.reply) {
		case 0:
			flow->foots.reply = 1;
			found2 = g_sequence_lookup(udpv4flows, flow, cmp_udpv4flows, NULL);
			flow->foots.reply = 0;
			break;
		case 1:
			flow->foots.reply = 0;
			found2 = g_sequence_lookup(udpv4flows, flow, cmp_udpv4flows, NULL);
			flow->foots.reply = 1;
			break;
		}

		if (found2 == NULL)
			EXITERR("BUG: add_udpv4traces");

		found = found2;
	}

	ptr = g_sequence_get(found);

	if (ptr->foots.traced == 1)
		return 0;

	ptr->foots.traced = 1;

	add_trace_udpv4flow(ptr);

	g_timeout_add_seconds(30, del_trace_udpv4flow_wrap, ptr);

	return 0;
}

gint add_icmpv4traces(struct icmpv4flow *flow)
{
	struct icmpv4flow *ptr;
	GSequenceIter *found = NULL, *found2 = NULL;

	found = g_sequence_lookup(icmpv4flows, flow, cmp_icmpv4flows, NULL);

	if (found == NULL) {

		switch (flow->foots.reply) {
		case 0:
			flow->foots.reply = 1;
			found2 = g_sequence_lookup(icmpv4flows, flow, cmp_icmpv4flows, NULL);
			flow->foots.reply = 0;
			break;
		case 1:
			flow->foots.reply = 0;
			found2 = g_sequence_lookup(icmpv4flows, flow, cmp_icmpv4flows, NULL);
			flow->foots.reply = 1;
			break;
		}

		if (found2 == NULL)
			EXITERR("BUG: add_icmpv4traces");

		found = found2;
	}

	ptr = g_sequence_get(found);

	if (ptr->foots.traced == 1)
		return 0;

	ptr->foots.traced = 1;

	add_trace_icmpv4flow(ptr);

	g_timeout_add_seconds(30, del_trace_icmpv4flow_wrap, ptr);

	return 0;
}

gint add_tcpv6traces(struct tcpv6flow *flow)
{
	struct tcpv6flow *ptr;
	GSequenceIter *found = NULL, *found2 = NULL;

	found = g_sequence_lookup(tcpv6flows, flow, cmp_tcpv6flows, NULL);

	if (found == NULL) {

		switch (flow->foots.reply) {
		case 0:
			flow->foots.reply = 1;
			found2 = g_sequence_lookup(tcpv6flows, flow, cmp_tcpv6flows, NULL);
			flow->foots.reply = 0;
			break;
		case 1:
			flow->foots.reply = 0;
			found2 = g_sequence_lookup(tcpv6flows, flow, cmp_tcpv6flows, NULL);
			flow->foots.reply = 1;
			break;
		}

		if (found2 == NULL)
			EXITERR("BUG: add_tcpv6traces");

		found = found2;
	}

	ptr = g_sequence_get(found);

	if (ptr->foots.traced == 1)
		return 0;

	ptr->foots.traced = 1;

	add_trace_tcpv6flow(ptr);

	g_timeout_add_seconds(30, del_trace_tcpv6flow_wrap, ptr);

	return 0;
}

gint add_udpv6traces(struct udpv6flow *flow)
{
	struct udpv6flow *ptr;
	GSequenceIter *found = NULL, *found2 = NULL;

	found = g_sequence_lookup(udpv6flows, flow, cmp_udpv6flows, NULL);

	if (found == NULL) {

		switch (flow->foots.reply) {
		case 0:
			flow->foots.reply = 1;
			found2 = g_sequence_lookup(udpv6flows, flow, cmp_udpv6flows, NULL);
			flow->foots.reply = 0;
			break;
		case 1:
			flow->foots.reply = 0;
			found2 = g_sequence_lookup(udpv6flows, flow, cmp_udpv6flows, NULL);
			flow->foots.reply = 1;
			break;
		}

		if (found2 == NULL)
			EXITERR("BUG: add_udpv6traces");

		found = found2;
	}

	ptr = g_sequence_get(found);

	if (ptr->foots.traced == 1)
		return 0;


	ptr->foots.traced = 1;

	add_trace_udpv6flow(ptr);

	g_timeout_add_seconds(30, del_trace_udpv6flow_wrap, ptr);

	return 0;
}

gint add_icmpv6traces(struct icmpv6flow *flow)
{
	struct icmpv6flow *ptr;
	GSequenceIter *found = NULL, *found2 = NULL;

	found = g_sequence_lookup(icmpv6flows, flow, cmp_icmpv6flows, NULL);

	if (found == NULL) {

		switch (flow->foots.reply) {
		case 0:
			flow->foots.reply = 1;
			found2 = g_sequence_lookup(icmpv6flows, flow, cmp_icmpv6flows, NULL);
			flow->foots.reply = 0;
			break;
		case 1:
			flow->foots.reply = 0;
			found2 = g_sequence_lookup(icmpv6flows, flow, cmp_icmpv6flows, NULL);
			flow->foots.reply = 1;
			break;
		}

		if (found2 == NULL)
			EXITERR("BUG: add_icmpv6traces");

		found = found2;
	}

	ptr = g_sequence_get(found);

	if (ptr->foots.traced == 1)
		return 0;

	ptr->foots.traced = 1;

	add_trace_icmpv6flow(ptr);

	g_timeout_add_seconds(30, del_trace_icmpv6flow_wrap, ptr);

	return 0;
}

// ----

gint add_tcpv4trace(struct in_addr s, struct in_addr d, uint16_t ps, uint16_t pd, uint8_t r)
{
	struct tcpv4flow flow;

	memset(&flow, '0', sizeof(struct tcpv4flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.reply = r;

	add_tcpv4traces(&flow);

	return 0;
}

gint add_udpv4trace(struct in_addr s, struct in_addr d, uint16_t ps, uint16_t pd, uint8_t r)
{

	struct udpv4flow flow;

	memset(&flow, '0', sizeof(struct udpv4flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.reply = r;

	add_udpv4traces(&flow);

	return 0;
}

gint add_icmpv4trace(struct in_addr s, struct in_addr d, uint8_t ty, uint8_t co, uint8_t r)
{

	struct icmpv4flow flow;

	memset(&flow, '0', sizeof(struct icmpv4flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.type = ty;
	flow.base.code = co;
	flow.foots.reply = r;

	add_icmpv4traces(&flow);

	return 0;
}

gint add_tcpv6trace(struct in6_addr s, struct in6_addr d, uint16_t ps, uint16_t pd, uint8_t r)
{
	struct tcpv6flow flow;

	memset(&flow, '0', sizeof(struct tcpv6flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.reply = r;

	add_tcpv6traces(&flow);

	return 0;
}

gint add_udpv6trace(struct in6_addr s, struct in6_addr d, uint16_t ps, uint16_t pd, uint8_t r)
{
	struct udpv6flow flow;

	memset(&flow, '0', sizeof(struct udpv6flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.reply = r;

	add_udpv6traces(&flow);

	return 0;
}

gint add_icmpv6trace(struct in6_addr s, struct in6_addr d, uint8_t ty, uint8_t co, uint8_t r)
{

	struct icmpv6flow flow;

	memset(&flow, '0', sizeof(struct icmpv6flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.type = ty;
	flow.base.code = co;
	flow.foots.reply = r;

	add_icmpv6traces(&flow);

	return 0;
}

// ----

void nfnetlink_start(void)
{
	gint filed;

	if (system("modprobe nfnetlink_log") < 0)
		EXITERR("could not load nfnetlink module")

	// nfnetlink_log be the default logging mech for ipv4 (proto = 2)

	if ((filed = open("/proc/sys/net/netfilter/nf_log/2", O_RDWR)) < 0)
		EXITERR("could not open sysfs netfilter file");

	if ((dprintf(filed, "nfnetlink_log\n")) < 0)
		EXITERR("could not write to sysfs");

	close(filed);

	// and for ipv6 (proto = 10)

	if ((filed = open("/proc/sys/net/netfilter/nf_log/10", O_RDWR)) < 0)
		EXITERR("could not open sysfs netfilter file");

	if ((dprintf(filed, "nfnetlink_log\n")) < 0)
		EXITERR("could not write to sysfs");

	close(filed);
}

// ----

gint iptables_leftovers(void)
{
	gint ret = 0, i = 0;

	// this is a brute force attempt of cleaning up previous run
	// (as conntracker crashes might lead to netfilter leftovers)
	// note: these don't show up errors, that is on purpose

	for (i = 0; i < 5; i++) {
		ret |= iptables_cleanup_oper(1, ipv4bin);
		ret |= iptables_cleanup_oper(1, ipv6bin);
		ret |= del_conntrack_oper(1, ipv4bin);
		ret |= del_conntrack_oper(1, ipv6bin);
	}

	// ignoring ret for now, as errors are accepted

	return 0;
}
