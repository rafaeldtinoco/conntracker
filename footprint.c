/*
 * (C) 2021 by Rafael David Tinoco <rafael.tinoco@ibm.com>
 * (C) 2021 by Rafael David Tinoco <rafaeldtinoco@ubuntu.com>
 */

#include "footprint.h"
#include "flows.h"

extern GSequence *tcpv4flows;
extern GSequence *udpv4flows;
extern GSequence *icmpv4flows;
extern GSequence *tcpv6flows;
extern GSequence *udpv6flows;
extern GSequence *icmpv6flows;

gint cmp_footprint(gconstpointer ptr_one, gconstpointer ptr_two, gpointer data)
{
	gint res;
	const struct footprint *one = ptr_one, *two = ptr_two;

	// compare netfilter tables
	if (one->table < two->table)
		return LESS;
	if (one->table > two->table)
		return MORE;

	if (one->table == two->table) {

		// compare netfilter chains
		res = g_strcmp0(one->chain, two->chain);
		if (res < 0)
			return LESS;
		if (res > 0)
			return MORE;

		if (res == 0) {

			// compare netfilter types
			if (one->type < two->type)
				return LESS;
			if (one->type > two->type)
				return MORE;

			if (one->type == two->type) {
				if (one->position < two->position)
					return LESS;
				if (one->position > two->position)
					return MORE;
			}
		}
	}

	return EQUAL;
}

// ----

gint add_tcpv4fps(struct tcpv4flow *flow, struct footprint *fp)
{
	struct tcpv4flow *ptr;
	struct footprint *newfp;
	GSequenceIter *tcpv4found, *fpfound;

	tcpv4found = g_sequence_lookup(tcpv4flows, flow, cmp_tcpv4flows, NULL);

	if (tcpv4found == NULL)
		goto inserted;

	// alloc a new footprint to lookup and, if needed, add

	ptr = g_sequence_get(tcpv4found);
	newfp = g_malloc0(sizeof(struct footprint));
	memcpy(newfp, fp, sizeof(struct footprint));

	fpfound = g_sequence_lookup(ptr->foots.fp, newfp, cmp_footprint, NULL);

	// footprint already exists, ignore

	if (fpfound != NULL)
		goto noneed;

	g_sequence_insert_sorted(ptr->foots.fp, newfp, cmp_footprint, NULL);
	goto inserted;

noneed:
	g_free(newfp);

inserted:
	return SUCCESS;
}

gint add_udpv4fps(struct udpv4flow *flow, struct footprint *fp)
{
	struct udpv4flow *ptr;
	struct footprint *newfp;
	GSequenceIter *udpv4found, *fpfound;

	udpv4found = g_sequence_lookup(udpv4flows, flow, cmp_udpv4flows, NULL);

	if (udpv4found == NULL)
		goto inserted;

	ptr = g_sequence_get(udpv4found);
	newfp = g_malloc0(sizeof(struct footprint));
	memcpy(newfp, fp, sizeof(struct footprint));

	fpfound = g_sequence_lookup(ptr->foots.fp, newfp, cmp_footprint, NULL);

	if (fpfound != NULL)
		goto noneed;

	g_sequence_insert_sorted(ptr->foots.fp, newfp, cmp_footprint, NULL);
	goto inserted;

noneed:
	g_free(newfp);

inserted:
	return SUCCESS;
}

gint add_icmpv4fps(struct icmpv4flow *flow, struct footprint *fp)
{
	struct icmpv4flow *ptr;
	struct footprint *newfp;
	GSequenceIter *icmpv4found, *fpfound;

	icmpv4found = g_sequence_lookup(icmpv4flows, flow, cmp_icmpv4flows, NULL);

	if (icmpv4found == NULL)
		goto inserted;

	ptr = g_sequence_get(icmpv4found);
	newfp = g_malloc0(sizeof(struct footprint));
	memcpy(newfp, fp, sizeof(struct footprint));

	fpfound = g_sequence_lookup(ptr->foots.fp, newfp, cmp_footprint, NULL);

	if (fpfound != NULL)
		goto noneed;

	g_sequence_insert_sorted(ptr->foots.fp, newfp, cmp_footprint, NULL);
	goto inserted;

noneed:
	g_free(newfp);

inserted:
	return SUCCESS;
}

gint add_tcpv6fps(struct tcpv6flow *flow, struct footprint *fp)
{
	struct tcpv6flow *ptr;
	struct footprint *newfp;
	GSequenceIter *tcpv6found, *fpfound;

	tcpv6found = g_sequence_lookup(tcpv6flows, flow, cmp_tcpv6flows, NULL);

	if (tcpv6found == NULL)
		goto inserted;

	ptr = g_sequence_get(tcpv6found);
	newfp = g_malloc0(sizeof(struct footprint));
	memcpy(newfp, fp, sizeof(struct footprint));

	fpfound = g_sequence_lookup(ptr->foots.fp, newfp, cmp_footprint, NULL);

	if (fpfound != NULL)
		goto noneed;

	g_sequence_insert_sorted(ptr->foots.fp, newfp, cmp_footprint, NULL);
	goto inserted;

noneed:
	g_free(newfp);

inserted:
	return SUCCESS;
}

gint add_udpv6fps(struct udpv6flow *flow, struct footprint *fp)
{
	struct udpv6flow *ptr;
	struct footprint *newfp;
	GSequenceIter *udpv6found, *fpfound;

	udpv6found = g_sequence_lookup(udpv6flows, flow, cmp_udpv6flows, NULL);

	if (udpv6found == NULL)
		goto inserted;

	ptr = g_sequence_get(udpv6found);
	newfp = g_malloc0(sizeof(struct footprint));
	memcpy(newfp, fp, sizeof(struct footprint));

	fpfound = g_sequence_lookup(ptr->foots.fp, newfp, cmp_footprint, NULL);

	if (fpfound != NULL)
		goto noneed;

	g_sequence_insert_sorted(ptr->foots.fp, newfp, cmp_footprint, NULL);
	goto inserted;

noneed:
	g_free(newfp);

inserted:
	return SUCCESS;
}

gint add_icmpv6fps(struct icmpv6flow *flow, struct footprint *fp)
{
	struct icmpv6flow *ptr;
	struct footprint *newfp;
	GSequenceIter *icmpv6found, *fpfound;

	icmpv6found = g_sequence_lookup(icmpv6flows, flow, cmp_icmpv6flows, NULL);

	if (icmpv6found == NULL)
		goto inserted;

	ptr = g_sequence_get(icmpv6found);
	newfp = g_malloc0(sizeof(struct footprint));
	memcpy(newfp, fp, sizeof(struct footprint));

	fpfound = g_sequence_lookup(ptr->foots.fp, newfp, cmp_footprint, NULL);

	if (fpfound != NULL)
		goto noneed;

	g_sequence_insert_sorted(ptr->foots.fp, newfp, cmp_footprint, NULL);
	goto inserted;

noneed:
	g_free(newfp);

inserted:
	return SUCCESS;
}

// ----

gint add_tcpv4fp(struct in_addr s, struct in_addr d,
		uint16_t ps, uint16_t pd, uint8_t r,
		struct footprint *fp)
{

	struct tcpv4flow flow;

	memset(&flow, '0', sizeof(struct tcpv4flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.reply = r;

	add_tcpv4fps(&flow, fp);

	return SUCCESS;
}

gint add_udpv4fp(struct in_addr s,struct in_addr d,
		uint16_t ps, uint16_t pd, uint8_t r,
		struct footprint *fp)
{
	struct udpv4flow flow;

	memset(&flow, '0', sizeof(struct udpv4flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.reply = r;

	add_udpv4fps(&flow, fp);

	return SUCCESS;
}

gint add_icmpv4fp(struct in_addr s, struct in_addr d,
		uint8_t ps, uint8_t pd, uint8_t r,
		struct footprint *fp)
{
	struct icmpv4flow flow;
	memset(&flow, '0', sizeof(struct icmpv4flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.type = ps;
	flow.base.code = pd;
	flow.foots.reply = r;

	add_icmpv4fps(&flow, fp);

	return SUCCESS;
}

gint add_tcpv6fp(struct in6_addr s, struct in6_addr d,
		uint16_t ps, uint16_t pd, uint8_t r,
		struct footprint *fp)
{
	struct tcpv6flow flow;

	memset(&flow, '0', sizeof(struct tcpv6flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.reply = r;

	add_tcpv6fps(&flow, fp);

	return SUCCESS;
}

gint add_udpv6fp(struct in6_addr s, struct in6_addr d,
		uint16_t ps, uint16_t pd, uint8_t r,
		struct footprint *fp)
{
	struct udpv6flow flow;

	memset(&flow, '0', sizeof(struct udpv6flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.reply = r;

	add_udpv6fps(&flow, fp);

	return SUCCESS;
}

gint add_icmpv6fp(struct in6_addr s, struct in6_addr d,
		uint8_t ps, uint8_t pd, uint8_t r,
		struct footprint *fp)
{
	struct icmpv6flow flow;

	memset(&flow, '0', sizeof(struct icmpv6flow));

	flow.addrs.src = s;
	flow.addrs.dst = d;
	flow.base.type = ps;
	flow.base.code = pd;
	flow.foots.reply = r;

	add_icmpv6fps(&flow, fp);

	return SUCCESS;
}

// ----

void out_footprint(gpointer data, gpointer user_data)
{
	static int times = 0;
	gchar *table, *type;
	struct footprint *fp = data;

	switch (fp->table) {
	case FOOTPRINT_TABLE_RAW:
		table = "raw";
		break;
	case FOOTPRINT_TABLE_MANGLE:
		table = "mangle";
		break;
	case FOOTPRINT_TABLE_NAT:
		table = "nat";
		break;
	case FOOTPRINT_TABLE_FILTER:
		table = "filter";
		break;
	default:
		table = "unknown";
		break;
	}

	switch (fp->type) {
	case FOOTPRINT_TYPE_POLICY:
		type = "policy";
		break;
	case FOOTPRINT_TYPE_RULE:
		type = "rule";
		break;
	case FOOTPRINT_TYPE_RETURN:
		type = "return";
		break;
	default:
		type = "unknown";
		break;
	}

	dprintf(logfd, "\t\t\t\ttable: %s, chain: %s, type: %s, position: %u\n",
			table, fp->chain, type, fp->position);
}

// ----

void cleanfp(gpointer data)
{
	g_free(data);
}
