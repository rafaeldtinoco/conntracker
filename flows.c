/*
 * (C) 2021 by Rafael David Tinoco <rafael.tinoco@ibm.com>
 * (C) 2021 by Rafael David Tinoco <rafaeldtinoco@ubuntu.com>
 */

#include "flows.h"

// seqs stored in memory

GSequence *tcpv4flows;
GSequence *udpv4flows;
GSequence *icmpv4flows;
GSequence *tcpv6flows;
GSequence *udpv6flows;
GSequence *icmpv6flows;

gchar *ipv4_str(struct in_addr *addr)
{
	gchar temp[INET_ADDRSTRLEN];

	memset(temp, 0, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, addr, temp, INET_ADDRSTRLEN);

	return g_strdup(temp);
}

gchar *ipv6_str(struct in6_addr *addr)
{
	gchar temp[INET6_ADDRSTRLEN];

	memset(temp, 0, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, addr, temp, INET6_ADDRSTRLEN);

	return g_strdup(temp);
}

// ----

gint
cmp_ipv4base(struct ipv4base one, struct ipv4base two)
{
	if (one.src.s_addr < two.src.s_addr)
		return LESS;
	if (one.src.s_addr > two.src.s_addr)
		return MORE;

	if (one.src.s_addr == two.src.s_addr)
	{
		if (one.dst.s_addr < two.dst.s_addr)
			return LESS;
		if (one.dst.s_addr > two.dst.s_addr)
			return MORE;
	}

	return EQUAL;
}

gint
cmp_portbase(struct portbase one, struct portbase two)
{
	if (one.dst < two.dst)
		return LESS;
	if (one.dst > two.dst)
		return MORE;

	if (one.dst == two.dst)
	{
		if (one.src < two.src)
			return LESS;
		if (one.src > two.src)
			return MORE;
	}

	return EQUAL;
}

gint
cmp_icmpbase(struct icmpbase one, struct icmpbase two)
{
	if (one.type < two.type)
		return LESS;
	if (one.type > two.type)
		return MORE;

	if (one.type == two.type)
	{
		if (one.code < two.code)
			return LESS;
		if (one.code > two.code)
			return MORE;
	}

	return EQUAL;
}

gint
cmp_ipv6base(struct ipv6base one, struct ipv6base two)
{
	/* ipv6 sorting done through its string as its easier */
	int res = 0;
	gchar *str1, *str2;

	str1 = ipv6_str(&one.src);
	str2 = ipv6_str(&two.src);

	res = g_strcmp0(str1, str2);

	g_free(str1);
	g_free(str2);

	if (res < 0)
		return LESS;
	if (res > 0)
		return MORE;

	if (res == 0)
	{
		str1 = ipv6_str(&one.dst);
		str2 = ipv6_str(&two.dst);

		res = g_strcmp0(str1, str2);

		g_free(str1);
		g_free(str2);

		if (res < 0)
			return LESS;
		if (res > 0)
			return MORE;
	}

	return EQUAL;
}

// ----

gint cmp_tcpv4flow(struct tcpv4flow *one, struct tcpv4flow *two)
{
	int res;

	if ((res = cmp_ipv4base(one->addrs, two->addrs)) != EQUAL)
		return res;
	if ((res = cmp_portbase(one->base, two->base)) != EQUAL)
		return res;

	if (one->foots.reply < two->foots.reply)
		return LESS;
	if (one->foots.reply > two->foots.reply)
		return MORE;

	return EQUAL;
}

gint cmp_udpv4flow(struct udpv4flow *one, struct udpv4flow *two)
{
	int res;

	if ((res = cmp_ipv4base(one->addrs, two->addrs)) != EQUAL)
		return res;
	if ((res = cmp_portbase(one->base, two->base)) != EQUAL)
		return res;

	if (one->foots.reply < two->foots.reply)
		return LESS;
	if (one->foots.reply > two->foots.reply)
		return MORE;

	return EQUAL;
}

gint cmp_icmpv4flow(struct icmpv4flow *one, struct icmpv4flow *two)
{
	int res;

	if ((res = cmp_ipv4base(one->addrs, two->addrs)) != EQUAL)
		return res;
	if ((res = cmp_icmpbase(one->base, two->base)) != EQUAL)
		return res;

	if (one->foots.reply < two->foots.reply)
		return LESS;
	if (one->foots.reply > two->foots.reply)
		return MORE;

	return EQUAL;
}

gint cmp_tcpv6flow(struct tcpv6flow *one, struct tcpv6flow *two)
{
	int res;

	if ((res = cmp_ipv6base(one->addrs, two->addrs)) != EQUAL)
		return res;
	if ((res = cmp_portbase(one->base, two->base)) != EQUAL)
		return res;

	if (one->foots.reply < two->foots.reply)
		return LESS;
	if (one->foots.reply > two->foots.reply)
		return MORE;

	return EQUAL;
}

gint cmp_udpv6flow(struct udpv6flow *one, struct udpv6flow *two)
{
	int res;

	if ((res = cmp_ipv6base(one->addrs, two->addrs)) != EQUAL)
		return res;
	if ((res = cmp_portbase(one->base, two->base)) != EQUAL)
		return res;

	if (one->foots.reply < two->foots.reply)
		return LESS;
	if (one->foots.reply > two->foots.reply)
		return MORE;

	return EQUAL;
}

gint cmp_icmpv6flow(struct icmpv6flow *one, struct icmpv6flow *two)
{
	int res;

	if ((res = cmp_ipv6base(one->addrs, two->addrs)) != EQUAL)
		return res;
	if ((res = cmp_icmpbase(one->base, two->base)) != EQUAL)
		return res;

	if (one->foots.reply < two->foots.reply)
		return LESS;
	if (one->foots.reply > two->foots.reply)
		return MORE;

	return EQUAL;
}

// ----

gint cmp_tcpv4flows(gconstpointer ptr_one, gconstpointer ptr_two, gpointer data)
{
	struct tcpv4flow *one = (struct tcpv4flow*) ptr_one;
	struct tcpv4flow *two = (struct tcpv4flow*) ptr_two;

	return cmp_tcpv4flow(one, two);
}

gint cmp_udpv4flows(gconstpointer ptr_one, gconstpointer ptr_two, gpointer data)
{
	struct udpv4flow *one = (struct udpv4flow*) ptr_one;
	struct udpv4flow *two = (struct udpv4flow*) ptr_two;

	return cmp_udpv4flow(one, two);
}

gint cmp_icmpv4flows(gconstpointer ptr_one, gconstpointer ptr_two, gpointer data)
{
	struct icmpv4flow *one = (struct icmpv4flow*) ptr_one;
	struct icmpv4flow *two = (struct icmpv4flow*) ptr_two;

	return cmp_icmpv4flow(one, two);
}

gint cmp_tcpv6flows(gconstpointer ptr_one, gconstpointer ptr_two, gpointer data)
{
	struct tcpv6flow *one = (struct tcpv6flow*) ptr_one;
	struct tcpv6flow *two = (struct tcpv6flow*) ptr_two;

	return cmp_tcpv6flow(one, two);
}

gint cmp_udpv6flows(gconstpointer ptr_one, gconstpointer ptr_two, gpointer data)
{
	struct udpv6flow *one = (struct udpv6flow*) ptr_one;
	struct udpv6flow *two = (struct udpv6flow*) ptr_two;

	return cmp_udpv6flow(one, two);
}

gint cmp_icmpv6flows(gconstpointer ptr_one, gconstpointer ptr_two, gpointer data)
{
	struct icmpv6flow *one = (struct icmpv6flow*) ptr_one;
	struct icmpv6flow *two = (struct icmpv6flow*) ptr_two;

	return cmp_icmpv6flow(one, two);
}

// ----

gint add_tcpv4flows(struct tcpv4flow *flow)
{
	struct tcpv4flow *temp, *ptr;
	GSequenceIter *found, *found2;

	temp = g_malloc0(sizeof(struct tcpv4flow));
	memcpy(temp, flow, sizeof(struct tcpv4flow));
	found = g_sequence_lookup(tcpv4flows, temp, cmp_tcpv4flows, NULL);

	if (found != NULL)
		goto noneed;

	switch (temp->foots.reply) {
	case 0:
		// check if confirmed flow exists. if not, add an unconfirmed flow

		temp->foots.reply = 1;
		found2 = g_sequence_lookup(tcpv4flows, temp, cmp_tcpv4flows, NULL);
		temp->foots.reply = 0;

		if (found2 == NULL) {
			/* create the footprint sequence (for tracing) */
			temp->foots.fp = g_sequence_new(cleanfp);
			g_sequence_insert_sorted(tcpv4flows, temp, cmp_tcpv4flows, NULL);
			goto inserted;
		}
		break;
	case 1:
		 // if it does confirm it, if not create and confirm it

		temp->foots.reply = 0;
		found2 = g_sequence_lookup(tcpv4flows, temp, cmp_tcpv4flows, NULL);
		if (found2 != NULL) {
			ptr = g_sequence_get(found2);
			ptr->foots.reply = 1;
		} else {
			/* create the footprint sequence (for tracing) */
			temp->foots.fp = g_sequence_new(cleanfp);
			g_sequence_insert_sorted(tcpv4flows, temp, cmp_tcpv4flows, NULL);
			goto inserted;
		}
		break;
	}

noneed:
	g_free(temp);

inserted:
	return 0;
}

gint add_udpv4flows(struct udpv4flow *flow)
{
	struct udpv4flow *temp, *ptr;
	GSequenceIter *found, *found2;

	temp = g_malloc0(sizeof(struct udpv4flow));
	memcpy(temp, flow, sizeof(struct udpv4flow));
	found = g_sequence_lookup(udpv4flows, temp, cmp_udpv4flows, NULL);

	if (found != NULL)
		goto noneed;

	switch (temp->foots.reply) {
	case 0:
		temp->foots.reply = 1;
		found2 = g_sequence_lookup(udpv4flows, temp, cmp_udpv4flows, NULL);
		temp->foots.reply = 0;

		if (found2 == NULL) {
			temp->foots.fp = g_sequence_new(cleanfp);
			g_sequence_insert_sorted(udpv4flows, temp, cmp_udpv4flows, NULL);
			goto inserted;
		}
		break;
	case 1:
		temp->foots.reply = 0;
		found2 = g_sequence_lookup(udpv4flows, temp, cmp_udpv4flows, NULL);
		if (found2 != NULL) {
			ptr = g_sequence_get(found2);
			ptr->foots.reply = 1;
		} else {
			temp->foots.fp = g_sequence_new(cleanfp);
			g_sequence_insert_sorted(udpv4flows, temp, cmp_udpv4flows, NULL);
			goto inserted;
		}
		break;
	}

noneed:
	g_free(temp);

inserted:
	return 0;
}

gint add_icmpv4flows(struct icmpv4flow *flow)
{
	struct icmpv4flow *temp, *ptr;
	GSequenceIter *found, *found2;

	temp = g_malloc0(sizeof(struct icmpv4flow));
	memcpy(temp, flow, sizeof(struct icmpv4flow));
	found = g_sequence_lookup(icmpv4flows, temp, cmp_icmpv4flows, NULL);

	if (found != NULL)
		goto noneed;

	switch (temp->foots.reply) {
	case 0:
		temp->foots.reply = 1;
		found2 = g_sequence_lookup(icmpv4flows, temp, cmp_icmpv4flows, NULL);
		temp->foots.reply = 0;

		if (found2 == NULL) {
			temp->foots.fp = g_sequence_new(cleanfp);
			g_sequence_insert_sorted(icmpv4flows, temp, cmp_icmpv4flows, NULL);
			goto inserted;
		}
		break;
	case 1:
		temp->foots.reply = 0;
		found2 = g_sequence_lookup(icmpv4flows, temp, cmp_icmpv4flows, NULL);
		if (found2 != NULL) {
			ptr = g_sequence_get(found2);
			ptr->foots.reply = 1;
		} else {
			temp->foots.fp = g_sequence_new(cleanfp);
			g_sequence_insert_sorted(icmpv4flows, temp, cmp_icmpv4flows, NULL);
			goto inserted;
		}
		break;
	}

noneed:
	g_free(temp);

inserted:
	return 0;
}

gint add_tcpv6flows(struct tcpv6flow *flow)
{
	struct tcpv6flow *temp, *ptr;
	GSequenceIter *found, *found2;

	temp = g_malloc0(sizeof(struct tcpv6flow));
	memcpy(temp, flow, sizeof(struct tcpv6flow));
	found = g_sequence_lookup(tcpv6flows, temp, cmp_tcpv6flows, NULL);

	if (found != NULL)
		goto noneed;

	switch (temp->foots.reply) {
	case 0:
		temp->foots.reply = 1;
		found2 = g_sequence_lookup(tcpv6flows, temp, cmp_tcpv6flows, NULL);
		temp->foots.reply = 0;

		if (found2 == NULL) {
			temp->foots.fp = g_sequence_new(cleanfp);
			g_sequence_insert_sorted(tcpv6flows, temp, cmp_tcpv6flows, NULL);
			goto inserted;
		}
		break;
	case 1:
		temp->foots.reply = 0;
		found2 = g_sequence_lookup(tcpv6flows, temp, cmp_tcpv6flows, NULL);
		if (found2 != NULL) {
			ptr = g_sequence_get(found2);
			ptr->foots.reply = 1;
		} else {
			temp->foots.fp = g_sequence_new(cleanfp);
			g_sequence_insert_sorted(tcpv6flows, temp, cmp_tcpv6flows, NULL);
			goto inserted;
		}
		break;
	}

noneed:
	g_free(temp);

inserted:
	return 0;
}

gint add_udpv6flows(struct udpv6flow *flow)
{
	struct udpv6flow *temp, *ptr;
	GSequenceIter *found, *found2;

	temp = g_malloc0(sizeof(struct udpv6flow));
	memcpy(temp, flow, sizeof(struct udpv6flow));
	found = g_sequence_lookup(udpv6flows, temp, cmp_udpv6flows, NULL);

	if (found != NULL)
		goto noneed;

	switch (temp->foots.reply) {
	case 0:
		temp->foots.reply = 1;
		found2 = g_sequence_lookup(udpv6flows, temp, cmp_udpv6flows, NULL);
		temp->foots.reply = 0;

		if (found2 == NULL) {
			temp->foots.fp = g_sequence_new(cleanfp);
			g_sequence_insert_sorted(udpv6flows, temp, cmp_udpv6flows, NULL);
			goto inserted;
		}
		break;
	case 1:
		temp->foots.reply = 0;
		found2 = g_sequence_lookup(udpv6flows, temp, cmp_udpv6flows, NULL);
		if (found2 != NULL) {
			ptr = g_sequence_get(found2);
			ptr->foots.reply = 1;
		} else {
			temp->foots.fp = g_sequence_new(cleanfp);
			g_sequence_insert_sorted(udpv6flows, temp, cmp_udpv6flows, NULL);
			goto inserted;
		}
		break;
	}

noneed:
	g_free(temp);

inserted:
	return 0;
}

gint add_icmpv6flows(struct icmpv6flow *flow)
{
	struct icmpv6flow *temp, *ptr;
	GSequenceIter *found, *found2;

	temp = g_malloc0(sizeof(struct icmpv6flow));
	memcpy(temp, flow, sizeof(struct icmpv6flow));
	found = g_sequence_lookup(icmpv6flows, temp, cmp_icmpv6flows, NULL);

	if (found != NULL)
		goto noneed;

	switch (temp->foots.reply) {
	case 0:
		temp->foots.reply = 1;
		found2 = g_sequence_lookup(icmpv6flows, temp, cmp_icmpv6flows, NULL);
		temp->foots.reply = 0;

		if (found2 == NULL) {
			temp->foots.fp = g_sequence_new(cleanfp);
			g_sequence_insert_sorted(icmpv6flows, temp, cmp_icmpv6flows, NULL);
			goto inserted;
		}
		break;
	case 1:
		temp->foots.reply = 0;
		found2 = g_sequence_lookup(icmpv6flows, temp, cmp_icmpv6flows, NULL);
		if (found2 != NULL) {
			ptr = g_sequence_get(found2);
			ptr->foots.reply = 1;
		} else {
			temp->foots.fp = g_sequence_new(cleanfp);
			g_sequence_insert_sorted(icmpv6flows, temp, cmp_icmpv6flows, NULL);
			goto inserted;
		}
		break;
	}

noneed:
	g_free(temp);

inserted:
	return 0;
}

// ----

gint add_tcpv4flow(struct in_addr s, struct in_addr d, uint16_t ps, uint16_t pd, uint8_t r)
{
	struct tcpv4flow flow;

	memset(&flow, '0', sizeof(struct tcpv4flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.reply = r;

	add_tcpv4flows(&flow);

	return 0;
}

gint add_udpv4flow(struct in_addr s, struct in_addr d, uint16_t ps, uint16_t pd, uint8_t r)
{
	struct udpv4flow flow;
	memset(&flow, '0', sizeof(struct udpv4flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.reply = r;

	add_udpv4flows(&flow);

	return 0;
}

gint add_icmpv4flow(struct in_addr s, struct in_addr d, uint8_t ps, uint8_t pd, uint8_t r)
{
	struct icmpv4flow flow;
	memset(&flow, '0', sizeof(struct icmpv4flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.type = ps;
	flow.base.code = pd;
	flow.foots.reply = r;

	add_icmpv4flows(&flow);

	return 0;
}

gint add_tcpv6flow(struct in6_addr s, struct in6_addr d, uint16_t ps, uint16_t pd, uint8_t r)
{
	struct tcpv6flow flow;
	memset(&flow, '0', sizeof(struct tcpv6flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.reply = r;

	add_tcpv6flows(&flow);

	return 0;
}

gint add_udpv6flow(struct in6_addr s, struct in6_addr d, uint16_t ps, uint16_t pd, uint8_t r)
{
	struct udpv6flow flow;
	memset(&flow, '0', sizeof(struct udpv6flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.reply = r;

	add_udpv6flows(&flow);

	return 0;
}

gint add_icmpv6flow(struct in6_addr s, struct in6_addr d, uint8_t ps, uint8_t pd, uint8_t r)
{
	struct icmpv6flow flow;
	memset(&flow, '0', sizeof(struct icmpv6flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.type = ps;
	flow.base.code = pd;
	flow.foots.reply = r;

	add_icmpv6flows(&flow);

	return 0;
}

// ----

void out_tcpv4flows(gpointer data, gpointer user_data)
{
	static int times = 0;
	gchar *src, *dst;
	struct tcpv4flow *flow = data;

	src = ipv4_str(&flow->addrs.src);
	dst = ipv4_str(&flow->addrs.dst);

	dprintf(logfd, " TCPv4 [%12d] src = %s (port=%u) to dst = %s (port=%u)%s\n", times++, src,
	                ntohs(flow->base.src), dst, ntohs(flow->base.dst),
	                flow->foots.reply ? " (confirmed)" : "");

	g_sequence_foreach(flow->foots.fp, out_footprint, NULL);

	g_free(src);
	g_free(dst);
}

void out_udpv4flows(gpointer data, gpointer user_data)
{
	static int times = 0;
	gchar *src, *dst;
	struct udpv4flow *flow = data;

	src = ipv4_str(&flow->addrs.src);
	dst = ipv4_str(&flow->addrs.dst);

	dprintf(logfd, " UDPv4 [%12d] src = %s (port=%u) to dst = %s (port=%u)%s\n", times++, src,
	                ntohs(flow->base.src), dst, ntohs(flow->base.dst),
	                flow->foots.reply ? " (confirmed)" : "");

	g_sequence_foreach(flow->foots.fp, out_footprint, NULL);

	g_free(src);
	g_free(dst);
}

void out_icmpv4flows(gpointer data, gpointer user_data)
{
	static int times = 0;
	gchar *src, *dst;
	struct icmpv4flow *flow = data;

	src = ipv4_str(&flow->addrs.src);
	dst = ipv4_str(&flow->addrs.dst);

	dprintf(logfd, "ICMPv4 [%12d] src = %s to dst = %s (type=%u | code=%u)%s\n", times++, src,
	                dst, (uint8_t) ntohs(flow->base.type), (uint8_t) ntohs(flow->base.code),
	                flow->foots.reply ? " (confirmed)" : "");

	g_sequence_foreach(flow->foots.fp, out_footprint, NULL);

	g_free(src);
	g_free(dst);
}

void out_tcpv6flows(gpointer data, gpointer user_data)
{
	static int times = 0;
	gchar *src, *dst;
	struct tcpv6flow *flow = data;

	src = ipv6_str(&flow->addrs.src);
	dst = ipv6_str(&flow->addrs.dst);

	dprintf(logfd, " TCPv6 [%12d] src = %s (port=%u) to dst = %s (port=%u)%s\n", times++, src,
	                ntohs(flow->base.src), dst, ntohs(flow->base.dst),
	                flow->foots.reply ? " (confirmed)" : "");

	g_sequence_foreach(flow->foots.fp, out_footprint, NULL);

	g_free(src);
	g_free(dst);
}

void out_udpv6flows(gpointer data, gpointer user_data)
{
	static int times = 0;
	gchar *src, *dst;
	struct udpv6flow *flow = data;

	src = ipv6_str(&flow->addrs.src);
	dst = ipv6_str(&flow->addrs.dst);

	dprintf(logfd, " UDPv6 [%12d] src = %s (port=%u) to dst = %s (port=%u)%s\n", times++, src,
	                ntohs(flow->base.src), dst, ntohs(flow->base.dst),
	                flow->foots.reply ? " (confirmed)" : "");

	g_sequence_foreach(flow->foots.fp, out_footprint, NULL);

	g_free(src);
	g_free(dst);
}

void out_icmpv6flows(gpointer data, gpointer user_data)
{
	static int times = 0;
	gchar *src, *dst;
	struct icmpv6flow *flow = data;

	src = ipv6_str(&flow->addrs.src);
	dst = ipv6_str(&flow->addrs.dst);

	dprintf(logfd, "ICMPv6 [%12d] src = %s to dst = %s (type=%u | code=%u)%s\n", times++, src,
	                dst, (uint8_t) ntohs(flow->base.type), (uint8_t) ntohs(flow->base.code),
	                flow->foots.reply ? " (confirmed)" : "");

	g_sequence_foreach(flow->foots.fp, out_footprint, NULL);

	g_free(src);
	g_free(dst);
}

// ----

void out_all(void)
{
	// tell user through syslog what logfile will contain the data

	out_logfile();

	// dump internal data into the logfile

	g_sequence_foreach(tcpv4flows, out_tcpv4flows, NULL);
	g_sequence_foreach(udpv4flows, out_udpv4flows, NULL);
	g_sequence_foreach(icmpv4flows, out_icmpv4flows, NULL);
	g_sequence_foreach(tcpv6flows, out_tcpv6flows, NULL);
	g_sequence_foreach(udpv6flows, out_udpv6flows, NULL);
	g_sequence_foreach(icmpv6flows, out_icmpv6flows, NULL);
}

// ----

void cleanflow_tcpv4(gpointer data)
{
	struct tcpv4flow *tcpv4 = data;
	g_sequence_free(tcpv4->foots.fp);
	g_free(data);
}

void cleanflow_udpv4(gpointer data)
{
	struct udpv4flow *udpv4 = data;
	g_sequence_free(udpv4->foots.fp);
	g_free(data);
}

void cleanflow_icmpv4(gpointer data)
{
	struct icmpv4flow *icmpv4 = data;
	g_sequence_free(icmpv4->foots.fp);
	g_free(data);
}

void cleanflow_tcpv6(gpointer data)
{
	struct tcpv6flow *tcpv6 = data;
	g_sequence_free(tcpv6->foots.fp);
	g_free(data);
}

void cleanflow_udpv6(gpointer data)
{
	struct udpv6flow *udpv6 = data;
	g_sequence_free(udpv6->foots.fp);
	g_free(data);
}

void cleanflow_icmpv6(gpointer data)
{
	struct icmpv6flow *icmpv6 = data;
	g_sequence_free(icmpv6->foots.fp);
	g_free(data);
}

// ----

void alloc_flows(void)
{
	tcpv4flows = g_sequence_new(cleanflow_tcpv4);
	udpv4flows = g_sequence_new(cleanflow_udpv4);
	icmpv4flows = g_sequence_new(cleanflow_icmpv4);
	tcpv6flows = g_sequence_new(cleanflow_tcpv6);
	udpv6flows = g_sequence_new(cleanflow_udpv6);
	icmpv6flows = g_sequence_new(cleanflow_icmpv6);
}

void free_flows(void)
{
	g_sequence_free(tcpv4flows);
	g_sequence_free(udpv4flows);
	g_sequence_free(icmpv4flows);
	g_sequence_free(tcpv6flows);
	g_sequence_free(udpv6flows);
	g_sequence_free(icmpv6flows);
}
