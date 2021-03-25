#ifndef BPFTRACKER_H_
#define BPFTRACKER_H_

int bpftracker_init(void);
int bpftracker_cleanup(void);
int bpftracker_poll(void *);
int bpftracker_fd(void);

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#define TASK_COMM_LEN 16

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

/* Protocol families.  */
#define PF_UNSPEC	0
#define PF_LOCAL	1
#define PF_UNIX		PF_LOCAL
#define PF_FILE		PF_LOCAL
#define PF_INET		2
#define PF_INET6	10
#define PF_PACKET	17
#define PF_MAX		45

/* Address families.  */
#define AF_UNSPEC	PF_UNSPEC
#define AF_LOCAL	PF_LOCAL
#define AF_UNIX		PF_UNIX
#define AF_INET		PF_INET
#define AF_INET6	PF_INET6
#define AF_ROUTE	PF_ROUTE
#define AF_PACKET	PF_PACKET
#define AF_MAX		PF_MAX

enum ev_type {
	EV_CONNECT  = 1,
	EV_CONNECT4 = 2,
	EV_CONNECT6 = 3,
};

struct data_t {
	u32 pid;			// proccess id
	u32 uid;			// user id
	u32 gid;			// group id
	u32 loginuid;			// real user (login/terminal)
	enum ev_type etype;		// event type
	char comm[TASK_COMM_LEN];	// command
	u8 proto;			// protocol
	__be16 sport;			// source port
	__be16 dport;			// destination port
	__be32 saddr;			// source address
	__be32 daddr;			// destination address
};

#endif // BPFTRACKER_H_
