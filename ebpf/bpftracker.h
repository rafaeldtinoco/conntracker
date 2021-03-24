#ifndef BPFTRACKER_H_
#define BPFTRACKER_H_

int bpftracker_init(void);
int bpftracker_cleanup(void);
int bpftracker_poll(void *);
int bpftracker_fd(void);

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

typedef unsigned int u32;

#define TASK_COMM_LEN 16
#define IPSET_MAXNAMELEN 32

enum ev_type {
	EXCHANGE_CREATE = 1,
	EXCHANGE_DESTROY = 2,
	EXCHANGE_FLUSH = 3,
	EXCHANGE_RENAME = 4,
	EXCHANGE_SWAP = 5,
	EXCHANGE_DUMP = 6,
	EXCHANGE_TEST = 7,
	EXCHANGE_ADD = 8,
	EXCHANGE_DEL = 9,
};

struct data_t {
	u32 pid;
	u32 uid;
	u32 gid;
	u32 loginuid;
	u32 ret;
	enum ev_type etype;
	char comm[TASK_COMM_LEN];
	char ipset_name[IPSET_MAXNAMELEN];
	char ipset_newname[IPSET_MAXNAMELEN];
	char ipset_type[IPSET_MAXNAMELEN];
};

typedef __u16 ip_set_id_t;

struct ip_set_net {
	struct ip_set  *ip_set_list;
	ip_set_id_t	ip_set_max;
	bool		is_deleted;
	bool		is_destroyed;
};

enum {
	IPSET_ATTR_UNSPEC,
	IPSET_ATTR_PROTOCOL,
	IPSET_ATTR_SETNAME,
	IPSET_ATTR_TYPENAME,
	IPSET_ATTR_SETNAME2 = IPSET_ATTR_TYPENAME,
	IPSET_ATTR_REVISION,
	IPSET_ATTR_FAMILY,
	IPSET_ATTR_FLAGS,
	IPSET_ATTR_DATA,
	IPSET_ATTR_ADT,
	IPSET_ATTR_LINENO,
	IPSET_ATTR_PROTOCOL_MIN,
	IPSET_ATTR_REVISION_MIN	= IPSET_ATTR_PROTOCOL_MIN,
	IPSET_ATTR_INDEX,
	__IPSET_ATTR_CMD_MAX,
};
#define IPSET_ATTR_CMD_MAX (__IPSET_ATTR_CMD_MAX - 1)

#define NLA_ALIGNTO		4
#define NLA_ALIGN(len)		(((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN		((int) NLA_ALIGN(sizeof(struct nlattr)))

#endif // BPFTRACKER_H_
