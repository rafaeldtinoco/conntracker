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

extern int logfd;
extern int amiadaemon;

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

gint add_tcpv4fpcmd(struct in_addr s, struct in_addr d, u16 ps, u16 pd, char *cmd)
{
	GSequenceIter *found;
	struct tcpv4flow flow, *exist;

	if (!cmd)
		return -1;

	memset(&flow, 0, sizeof(struct tcpv4flow));
	flow.addrs.src.s_addr = s.s_addr;
	flow.addrs.dst.s_addr = d.s_addr;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.cmd = NULL;

	found = g_sequence_lookup(tcpv4flows, &flow, cmp_tcpv4flows, NULL);
	if (found) {
		exist = g_sequence_get(found);
		if (exist->foots.cmd)
			g_free(exist->foots.cmd);
		exist->foots.cmd = strdup(cmd);
	} else
		DEBHERE("IMPOSSIBRU");

	return 0;
}

gint add_udpv4fpcmd(struct in_addr s, struct in_addr d, u16 ps, u16 pd, char *cmd)
{
	GSequenceIter *found;
	struct udpv4flow flow, *exist;

	if (!cmd)
		return -1;

	memset(&flow, 0, sizeof(struct udpv4flow));
	flow.addrs.src.s_addr = s.s_addr;
	flow.addrs.dst.s_addr = d.s_addr;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.cmd = NULL;

	found = g_sequence_lookup(udpv4flows, &flow, cmp_udpv4flows, NULL);
	if (found) {
		exist = g_sequence_get(found);
		if (exist->foots.cmd)
			g_free(exist->foots.cmd);
		exist->foots.cmd = strdup(cmd);
	} else
		DEBHERE("IMPOSSIBRU");

	return 0;
}

gint add_tcpv6fpcmd(struct in6_addr s, struct in6_addr d, u16 ps, u16 pd, char *cmd)
{
	GSequenceIter *found;
	struct tcpv6flow flow, *exist;

	if (!cmd)
		return -1;

	memset(&flow, 0, sizeof(struct tcpv6flow));

	memcpy(&flow.addrs.src, &s, sizeof(struct in6_addr));
	memcpy(&flow.addrs.dst, &d, sizeof(struct in6_addr));
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.cmd = NULL;

	found = g_sequence_lookup(tcpv6flows, &flow, cmp_tcpv6flows, NULL);
	if (found) {
		exist = g_sequence_get(found);
		if (exist->foots.cmd)
			g_free(exist->foots.cmd);
		exist->foots.cmd = strdup(cmd);
	} else
		DEBHERE("IMPOSSIBRU");

	return 0;
}

gint add_udpv6fpcmd(struct in6_addr s, struct in6_addr d, u16 ps, u16 pd, char *cmd)
{
	GSequenceIter *found;
	struct udpv6flow flow, *exist;

	if (!cmd)
		return -1;

	memset(&flow, 0, sizeof(struct udpv6flow));
	memcpy(&flow.addrs.src, &s, sizeof(struct in6_addr));
	memcpy(&flow.addrs.dst, &d, sizeof(struct in6_addr));
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.cmd = NULL;

	found = g_sequence_lookup(udpv6flows, &flow, cmp_udpv6flows, NULL);
	if (found) {
		exist = g_sequence_get(found);
		if (exist->foots.cmd)
			g_free(exist->foots.cmd);
		exist->foots.cmd = strdup(cmd);
	} else
		DEBHERE("IMPOSSIBRU");

	return 0;
}

// ----

gint add_tcpv4fps(struct tcpv4flow *givenflow, struct footprint *givenfp)
{
	GSequenceIter *foundflow, *foundfp;
	struct tcpv4flow *existingflow;
	struct footprint *newfp;

	foundflow = g_sequence_lookup(tcpv4flows, givenflow, cmp_tcpv4flows, NULL);
	if (!foundflow)
		return 0;

	existingflow = g_sequence_get(foundflow);

	newfp = g_malloc0(sizeof(struct footprint));
	memcpy(newfp, givenfp, sizeof(struct footprint));

	foundfp = g_sequence_lookup(existingflow->foots.fp, newfp, cmp_footprint, NULL);
	if (foundfp) {
		g_free(newfp);
		return 0;
	}
	g_sequence_insert_sorted(existingflow->foots.fp, newfp, cmp_footprint, NULL);

	return 0;
}

gint add_udpv4fps(struct udpv4flow *givenflow, struct footprint *givenfp)
{
	GSequenceIter *foundflow, *foundfp;
	struct udpv4flow *existingflow;
	struct footprint *newfp;

	foundflow = g_sequence_lookup(udpv4flows, givenflow, cmp_udpv4flows, NULL);
	if (!foundflow)
		return 0;

	existingflow = g_sequence_get(foundflow);

	newfp = g_malloc0(sizeof(struct footprint));
	memcpy(newfp, givenfp, sizeof(struct footprint));

	foundfp = g_sequence_lookup(existingflow->foots.fp, newfp, cmp_footprint, NULL);
	if (foundfp) {
		g_free(newfp);
		return 0;
	}
	g_sequence_insert_sorted(existingflow->foots.fp, newfp, cmp_footprint, NULL);

	return 0;
}

gint add_icmpv4fps(struct icmpv4flow *givenflow, struct footprint *givenfp)
{
	GSequenceIter *foundflow, *foundfp;
	struct icmpv4flow *existingflow;
	struct footprint *newfp;

	foundflow = g_sequence_lookup(icmpv4flows, givenflow, cmp_icmpv4flows, NULL);
	if (!foundflow)
		return 0;

	existingflow = g_sequence_get(foundflow);

	newfp = g_malloc0(sizeof(struct footprint));
	memcpy(newfp, givenfp, sizeof(struct footprint));

	foundfp = g_sequence_lookup(existingflow->foots.fp, newfp, cmp_footprint, NULL);
	if (foundfp) {
		g_free(newfp);
		return 0;
	}
	g_sequence_insert_sorted(existingflow->foots.fp, newfp, cmp_footprint, NULL);

	return 0;
}

gint add_tcpv6fps(struct tcpv6flow *givenflow, struct footprint *givenfp)
{
	GSequenceIter *foundflow, *foundfp;
	struct tcpv6flow *existingflow;
	struct footprint *newfp;

	foundflow = g_sequence_lookup(tcpv6flows, givenflow, cmp_tcpv6flows, NULL);
	if (!foundflow)
		return 0;

	existingflow = g_sequence_get(foundflow);

	newfp = g_malloc0(sizeof(struct footprint));
	memcpy(newfp, givenfp, sizeof(struct footprint));

	foundfp = g_sequence_lookup(existingflow->foots.fp, newfp, cmp_footprint, NULL);
	if (foundfp) {
		g_free(newfp);
		return 0;
	}
	g_sequence_insert_sorted(existingflow->foots.fp, newfp, cmp_footprint, NULL);

	return 0;
}

gint add_udpv6fps(struct udpv6flow *givenflow, struct footprint *givenfp)
{
	GSequenceIter *foundflow, *foundfp;
	struct udpv6flow *existingflow;
	struct footprint *newfp;

	foundflow = g_sequence_lookup(udpv6flows, givenflow, cmp_udpv6flows, NULL);
	if (!foundflow)
		return 0;

	existingflow = g_sequence_get(foundflow);

	newfp = g_malloc0(sizeof(struct footprint));
	memcpy(newfp, givenfp, sizeof(struct footprint));

	foundfp = g_sequence_lookup(existingflow->foots.fp, newfp, cmp_footprint, NULL);
	if (foundfp) {
		g_free(newfp);
		return 0;
	}
	g_sequence_insert_sorted(existingflow->foots.fp, newfp, cmp_footprint, NULL);

	return 0;
}

gint add_icmpv6fps(struct icmpv6flow *givenflow, struct footprint *givenfp)
{
	GSequenceIter *foundflow, *foundfp;
	struct icmpv6flow *existingflow;
	struct footprint *newfp;

	foundflow = g_sequence_lookup(icmpv6flows, givenflow, cmp_icmpv6flows, NULL);
	if (!foundflow)
		return 0;

	existingflow = g_sequence_get(foundflow);

	newfp = g_malloc0(sizeof(struct footprint));
	memcpy(newfp, givenfp, sizeof(struct footprint));

	foundfp = g_sequence_lookup(existingflow->foots.fp, newfp, cmp_footprint, NULL);
	if (foundfp) {
		g_free(newfp);
		return 0;
	}
	g_sequence_insert_sorted(existingflow->foots.fp, newfp, cmp_footprint, NULL);

	return 0;
}

// ----

gint add_tcpv4fp(struct in_addr s, struct in_addr d, u16 ps, u16 pd, struct footprint *fp)
{

	struct tcpv4flow flow;
	memset(&flow, 0, sizeof(struct tcpv4flow));

	flow.addrs.src.s_addr = s.s_addr;
	flow.addrs.dst.s_addr = d.s_addr;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.cmd = NULL;

	add_tcpv4fps(&flow, fp);

	return 0;
}

gint add_udpv4fp(struct in_addr s,struct in_addr d, u16 ps, u16 pd, struct footprint *fp)
{
	struct udpv4flow flow;
	memset(&flow, 0, sizeof(struct udpv4flow));

	flow.addrs.src.s_addr = s.s_addr;
	flow.addrs.dst.s_addr = d.s_addr;
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.cmd = NULL;

	add_udpv4fps(&flow, fp);

	return 0;
}

gint add_icmpv4fp(struct in_addr s, struct in_addr d, u8 ty, u8 co, struct footprint *fp)
{
	struct icmpv4flow flow;
	memset(&flow, 0, sizeof(struct icmpv4flow));

	flow.addrs.src.s_addr = s.s_addr;
	flow.addrs.dst.s_addr = d.s_addr;
	flow.base.type = ty;
	flow.base.code = co;
	flow.foots.cmd = NULL;

	add_icmpv4fps(&flow, fp);

	return 0;
}

gint add_tcpv6fp(struct in6_addr s, struct in6_addr d, u16 ps, u16 pd, struct footprint *fp)
{
	struct tcpv6flow flow;
	memset(&flow, 0, sizeof(struct tcpv6flow));

	memcpy(&flow.addrs.src, &s, sizeof(struct in6_addr));
	memcpy(&flow.addrs.dst, &d, sizeof(struct in6_addr));
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.cmd = NULL;

	add_tcpv6fps(&flow, fp);

	return 0;
}

gint add_udpv6fp(struct in6_addr s, struct in6_addr d, u16 ps, u16 pd, struct footprint *fp)
{
	struct udpv6flow flow;
	memset(&flow, '0', sizeof(struct udpv6flow));

	memcpy(&flow.addrs.src, &s, sizeof(struct in6_addr));
	memcpy(&flow.addrs.dst, &d, sizeof(struct in6_addr));
	flow.base.src = ps;
	flow.base.dst = pd;
	flow.foots.cmd = NULL;

	add_udpv6fps(&flow, fp);

	return 0;
}

gint add_icmpv6fp(struct in6_addr s, struct in6_addr d, u8 ty, u8 co, struct footprint *fp)
{
	struct icmpv6flow flow;
	memset(&flow, 0, sizeof(struct icmpv6flow));

	memcpy(&flow.addrs.src, &s, sizeof(struct in6_addr));
	memcpy(&flow.addrs.dst, &d, sizeof(struct in6_addr));
	flow.base.type = ty;
	flow.base.code = co;
	flow.foots.cmd = NULL;

	add_icmpv6fps(&flow, fp);

	return 0;
}

// ----

void out_footprint(gpointer data, gpointer user_data)
{
	uint32_t pos;
	gchar *table, *type;
	struct footprint *fp = data;

	// table

	switch (fp->table) {
	case FOOTPRINT_TABLE_RAW:
		return;
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

	// type

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

	// position

	pos = fp->position;

	// because of:
	//
	//-t mangle -I PREROUTING 1 -m conntrack ...
	//-t mangle -I FORWARD 1 -m conntrack ...
	//-t mangle -I OUTPUT 1 -m conntrack ...
	//
	// some positions need adjustment:
	//

	if (fp->table == FOOTPRINT_TABLE_MANGLE) {

		if (g_ascii_strcasecmp(fp->chain, "PREROUTING") == 0)
			pos--;

		if (g_ascii_strcasecmp(fp->chain, "FORWARD") == 0)
			pos--;

		if (g_ascii_strcasecmp(fp->chain, "OUTPUT") == 0)
			pos--;

	}

	if (pos == 0)
		return;

	// don't show position for chain policies

	if (fp->type == FOOTPRINT_TYPE_POLICY) {
		dprintf(logfd, "\t\t\t\ttable: %s, chain: %s, type: %s\n", table, fp->chain, type);
	} else {
		dprintf(logfd, "\t\t\t\ttable: %s, chain: %s, type: %s, position: %u\n",
			table, fp->chain, type, pos);
	}
}

// ----

void cleanfp(gpointer data)
{
	g_free(data);
}
