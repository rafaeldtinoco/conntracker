/*
 * (C) 2015 by Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>
 * (C) 2020 by Rafael David Tinoco <rafael.tinoco@ibm.com>
 */

#include <arpa/inet.h>
#include <errno.h>

#include "nlmsg.h"
#include "conntracker.h"

struct nlmsghdr *
nflog_nlmsg_put_header(char *buf, uint8_t type, uint8_t family, uint16_t qnum)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	struct nfgenmsg *nfg;

	nlh->nlmsg_type	= (NFNL_SUBSYS_ULOG << 8) | type;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = family;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(qnum);

	return nlh;
}

int nflog_attr_put_cfg_mode(struct nlmsghdr *nlh, uint8_t mode, uint32_t range)
{
	struct nfulnl_msg_config_mode nfmode = {
		.copy_mode = mode,
		.copy_range = htonl(range)
	};

	mnl_attr_put(nlh, NFULA_CFG_MODE, sizeof(nfmode), &nfmode);

	/* it may returns -1 in future */
	return 0;
}

int nflog_attr_put_cfg_cmd(struct nlmsghdr *nlh, uint8_t cmd)
{
	struct nfulnl_msg_config_cmd nfcmd = {
		.command = cmd
	};

	mnl_attr_put(nlh, NFULA_CFG_CMD, sizeof(nfcmd), &nfcmd);

	/* it may returns -1 in future */
	return 0;
}

static int nflog_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, NFULA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFULA_HWTYPE:		/* hardware type */
	case NFULA_HWLEN:		/* hardware header length */
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
			return MNL_CB_ERROR;
		break;
	case NFULA_MARK:		/* __u32 nfmark */
	case NFULA_IFINDEX_INDEV:	/* __u32 ifindex */
	case NFULA_IFINDEX_OUTDEV:	/* __u32 ifindex */
	case NFULA_IFINDEX_PHYSINDEV:	/* __u32 ifindex */
	case NFULA_IFINDEX_PHYSOUTDEV:	/* __u32 ifindex */
	case NFULA_UID:			/* user id of socket */
	case NFULA_SEQ:			/* instance-local sequence number */
	case NFULA_SEQ_GLOBAL:		/* global sequence number */
	case NFULA_GID:			/* group id of socket */
	case NFULA_CT_INFO:		/* enum ip_conntrack_info */
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			return MNL_CB_ERROR;
		break;
	case NFULA_PACKET_HDR:
		if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
		    sizeof(struct nfulnl_msg_packet_hdr)) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case NFULA_TIMESTAMP:		/* nfulnl_msg_packet_timestamp */
		if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
		    sizeof(struct nfulnl_msg_packet_timestamp)) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case NFULA_HWADDR:		/* nfulnl_msg_packet_hw */
		if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
		    sizeof(struct nfulnl_msg_packet_hw)) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case NFULA_PREFIX:		/* string prefix */
		if (mnl_attr_validate(attr, MNL_TYPE_NUL_STRING) < 0)
			return MNL_CB_ERROR;
		break;
	case NFULA_HWHEADER:		/* hardware header */
	case NFULA_PAYLOAD:		/* opaque data payload */
	case NFULA_CT:			/* nf_conntrack_netlink.h */
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

int nflog_nlmsg_parse(const struct nlmsghdr *nlh, struct nlattr **attr)
{
	return mnl_attr_parse(nlh, sizeof(struct nfgenmsg), nflog_parse_attr_cb, attr);
}

struct mnl_socket *ulognlct_open(void)
{
	int ret, recvbuf = 1024 * 1024;
	struct mnl_socket *nl;
	struct nlmsghdr *nlh;
	char buf[MNL_SOCKET_BUFFER_SIZE];

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		perror("mnl_socket_open");
		return NULL;
	}

	if (setsockopt(nl->fd, SOL_SOCKET, SO_RCVBUFFORCE, &recvbuf, sizeof(int))) {
		perror("setsockopt");
		return NULL;
	}

	// bind socket to task group pid
	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		return NULL;
	}

	// unbind net family
	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, 0);

	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_PF_UNBIND) < 0)
		return NULL;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		return NULL;

	// bind net family
	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, 0);

	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_PF_BIND) < 0)
		return NULL;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		return NULL;

	// bind ulog queue
	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, 0);

	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_BIND) < 0)
		return NULL;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		return NULL;

	// configure pkg delivery - to userland - mechanism
	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, 0);

	if (nflog_attr_put_cfg_mode(nlh, NFULNL_COPY_META, 0xffff) < 0)
		return NULL;

	// ask for conntrack information together with trace
	mnl_attr_put_u16(nlh, NFULA_CFG_FLAGS, htons(NFULNL_CFG_F_CONNTRACK));

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		return NULL;

	return nl;
}

int ulognlct_close(struct mnl_socket *sock)
{
	return mnl_socket_close(sock);
}
