/*
 * (C) 2021 by Rafael David Tinoco <rafael.tinoco@ibm.com>
 * (C) 2021 by Rafael David Tinoco <rafaeldtinoco@ubuntu.com>
 */

#include "iptables.h"
#include "flows.h"

/* seqs stored in memory */

extern GSequence *tcpv4flows;
extern GSequence *udpv4flows;
extern GSequence *icmpv4flows;
extern GSequence *tcpv6flows;
extern GSequence *udpv6flows;
extern GSequence *icmpv6flows;

/*
 * NOTE: without controlling iptables through these functions, one could simply
 * have 2 x IPv4 and 2 x IPV6 rules in both chains from the raw table:
 *
 * $ sudo iptables-legacy -t raw --list --numeric --line-numbers
 *   Chain PREROUTING (policy ACCEPT)
 *   num  target     prot opt source		destination
 *   1    ACCEPT     all  --  0.0.0.0/0		0.0.0.0/0	ctstate NEW,ESTABLISHED
 *   2    TRACE      all  --  0.0.0.0/0		0.0.0.0/0
 *
 *   Chain OUTPUT (policy ACCEPT)
 *   num  target     prot opt source		destination
 *   1    ACCEPT     all  --  0.0.0.0/0		0.0.0.0/0	ctstate NEW,ESTABLISHED
 *
 * $ sudo ip6tables-legacy -t raw --list --numeric --line-numbers
 *   Chain PREROUTING (policy ACCEPT)
 *   num  target     prot opt source		destination
 *   1    ACCEPT     all      ::/0		::/0		ctstate NEW,ESTABLISHED
 *   2    TRACE      all      ::/0		::/0
 *
 *   Chain OUTPUT (policy ACCEPT)
 *   num  target     prot opt source		destination
 *   1    ACCEPT     all      ::/0		::/0		ctstate NEW,ESTABLISHED
 *   2    TRACE      all      ::/0		::/0
 *
 *   this is enough for conntracker to work. Nevertheless, the intent here is to
 *   cause the minimum amount of overhead we can so, instead of having a very
 *   opened TRACE rule like the one above, we keep an opened conntrack rule - to
 *   make conntrack module to do the dirty job for us - but we only add the
 *   trace rules for those flows that were captured.
 *
 *   How it works:
 *
 *   0) MANDATORY: RAW table must not be used by any other tool (for your safeness)
 *   1) RAW table starts connection tracking for all NEW (and related) flows
 *   2) conntracker code is informed (libnetfilter_conntrack) and logs (in-memory) the flow
 *   3) conntracker adds ad-hoc TRACE for the flow just captured
 *   4) TRACE netfilter ulog (libnetfilter_log) informs netfilter hooks the flow passed by
 *   5) conntracker shuts down TRACE for the flow captured (and won't trace again the same flow)
 *   6) when finished, conntracker informs all flows
 *
 *   OBS: conntracker uses kernel connection tracker feature extensively and it
 *   is mandatory to have a conntrack match rule in the RAW table all the time,
 *   orelse this userland tool would not be able to keep track of the flows
 *   (that are being tracked by kernel and informed through a netlink
 *   interface).
 *
 *   Note: there is an on-going change from netfilter to nftables in most of
 *   Linux distributions. Commit 'conntracker: libnftnl example for the future'
 *   shows an example on how to implement this part without using "iptables"
 *   wrapper through a shell call, like being used now, by using netlink
 *   communication to add/remove nftables rules. Problem is that... we currently
 *   would have to support "iptables-legacy" (netfilter, with libiptc) and
 *   "iptables-nft" (nftables, with libnftnl) and it would make this over
 *   complicated. TODO: wait for nftables to be only available option and
 *   implement the functions bellow by using libnftnl.
 *
 */

char *ipv4bin = "/sbin/iptables";
char *ipv6bin = "/sbin/ip6tables";
char *flushraw = "-t raw --flush";
char *ctsufix = "-t raw -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT";

gint iptables_flush(char *bin)
{
	gchar cmd[1024];

	memset(cmd, 0, 1024);
	snprintf(cmd, 1024, "%s %s", bin, flushraw);

	return system(cmd);
}

gint iptables4_flush(void)
{
	return iptables_flush(ipv4bin);
}

gint iptables6_flush(void)
{
	return iptables_flush(ipv6bin);
}

gint iptables_cleanup(void)
{
	int ret = 0;

	ret |= iptables4_flush();
	ret |= iptables6_flush();

	return ret;
}

gint oper_conntrack(char *bin, char *mid)
{
	gchar cmd[1024];

	memset(cmd, 0, 1024);
	snprintf(cmd, 1024, "%s %s %s", bin, mid, ctsufix);

	return system(cmd);
}

gint add_conntrack_ipv4(void)
{
	gint ret = 0;

	ret |= oper_conntrack(ipv4bin, "-I OUTPUT 1");
	ret |= oper_conntrack(ipv4bin, "-I PREROUTING 1");

	return ret;
}

gint add_conntrack_ipv6(void)
{
	gint ret = 0;

	ret |= oper_conntrack(ipv6bin, "-I OUTPUT 1");
	ret |= oper_conntrack(ipv6bin, "-I PREROUTING 1");

	return ret;
}

gint add_conntrack(void)
{
	gint ret = 0;

	ret |= add_conntrack_ipv4();
	ret |= add_conntrack_ipv6();

	return ret;
}

gint del_conntrack_ipv4(void)
{
	gint ret = 0;

	ret |= oper_conntrack(ipv4bin, "-D OUTPUT");
	ret |= oper_conntrack(ipv4bin, "-D PREROUTING");

	return ret;
}

gint del_conntrack_ipv6(void)
{
	gint ret = 0;

	ret |= oper_conntrack(ipv6bin, "-D OUTPUT");
	ret |= oper_conntrack(ipv6bin, "-D PREROUTING");

	return ret;
}

gint del_conntrack(void)
{
	gint ret = 0;

	ret |= del_conntrack_ipv4();
	ret |= del_conntrack_ipv6();

	return ret;
}

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

// ----

gint del_trace_tcpv4flow_wrap(gpointer ptr)
{
	struct tcpv4flow *flow = ptr;

	del_trace_tcpv4flow(flow);

	// one time exec: disable future timeout callbacks

	return FALSE;
}

gint del_trace_udpv4flow_wrap(gpointer ptr)
{
	struct udpv4flow *flow = ptr;

	del_trace_udpv4flow(flow);

	return FALSE;
}

gint del_trace_icmpv4flow_wrap(gpointer ptr)
{
	struct icmpv4flow *flow = ptr;

	del_trace_icmpv4flow(flow);

	return FALSE;
}

gint del_trace_tcpv6flow_wrap(gpointer ptr)
{
	struct tcpv6flow *flow = ptr;

	del_trace_tcpv6flow(flow);

	return FALSE;
}

// ----

gint add_tcpv4traces(struct tcpv4flow *flow)
{
	struct tcpv4flow *ptr;
	GSequenceIter *found, *found2;

	gchar *src, *dst;
	uint16_t sport, dport;

	found = g_sequence_lookup(tcpv4flows, flow, cmp_tcpv4flows, NULL);

	src = ipv4_str(&flow->addrs.src);
	dst = ipv4_str(&flow->addrs.dst);

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

		if (found2 == NULL) {
			perror("BUG: add_tcpv4traces");
			exit(ERROR);
		}

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
		return SUCCESS;


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

	return SUCCESS;
}

gint add_udpv4traces(struct udpv4flow *flow)
{
	struct udpv4flow *ptr;
	GSequenceIter *found, *found2;

	gchar *src, *dst;
	uint16_t sport, dport;

	found = g_sequence_lookup(udpv4flows, flow, cmp_udpv4flows, NULL);

	src = ipv4_str(&flow->addrs.src);
	dst = ipv4_str(&flow->addrs.dst);

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

		if (found2 == NULL) {
			perror("BUG: add_udpv4traces");
			exit(ERROR);
		}

		found = found2;
	}

	ptr = g_sequence_get(found);

	if (ptr->foots.traced == 1)
		return SUCCESS;

	ptr->foots.traced = 1;

	add_trace_udpv4flow(ptr);

	g_timeout_add_seconds(30, del_trace_udpv4flow_wrap, ptr);

	return SUCCESS;
}

gint add_icmpv4traces(struct icmpv4flow *flow)
{
	struct icmpv4flow *ptr;
	GSequenceIter *found, *found2;

	gchar *src, *dst;
	uint16_t sport, dport;

	found = g_sequence_lookup(icmpv4flows, flow, cmp_icmpv4flows, NULL);

	src = ipv4_str(&flow->addrs.src);
	dst = ipv4_str(&flow->addrs.dst);

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

		if (found2 == NULL) {
			perror("BUG: add_icmpv4traces");
			exit(ERROR);
		}

		found = found2;
	}

	ptr = g_sequence_get(found);

	if (ptr->foots.traced == 1)
		return SUCCESS;

	ptr->foots.traced = 1;

	add_trace_icmpv4flow(ptr);

	g_timeout_add_seconds(30, del_trace_icmpv4flow_wrap, ptr);

	return SUCCESS;
}

gint add_tcpv6traces(struct tcpv6flow *flow)
{
	struct tcpv6flow *ptr;
	GSequenceIter *found, *found2;

	gchar *src, *dst;
	uint16_t sport, dport;

	found = g_sequence_lookup(tcpv6flows, flow, cmp_tcpv6flows, NULL);

	src = ipv6_str(&flow->addrs.src);
	dst = ipv6_str(&flow->addrs.dst);

	/*
	printf("DEBUG: TCPv6 src = %s (port=%u) to dst = %s (port=%u)%s\n",
			src, ntohs(flow->base.src), dst, ntohs(flow->base.dst),
			flow->foots.reply ? " (confirmed)" : "");
	*/

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

		if (found2 == NULL) {
			perror("BUG: add_tcpv6traces");
			exit(ERROR);
		}

		found = found2;
	}

	ptr = g_sequence_get(found);

	if (ptr->foots.traced == 1)
		return SUCCESS;


	ptr->foots.traced = 1;

	add_trace_tcpv6flow(ptr);

	g_timeout_add_seconds(30, del_trace_tcpv6flow_wrap, ptr);

	return SUCCESS;
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

	return SUCCESS;
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

	return SUCCESS;
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

	return SUCCESS;
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

	return SUCCESS;
}
