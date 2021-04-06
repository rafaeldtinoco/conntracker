#ifndef BPFTRACKER_H_
#define BPFTRACKER_H_

int bpftracker_init(void);
int bpftracker_cleanup(void);
int bpftracker_poll(void *);
int bpftracker_fd(void);

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

struct data_t {
	char comm[16];		// command
	u32  pid;		// proccess id
	u32  uid;		// user id
	u32  gid;		// group id
	u32  loginuid;		// real user (login/terminal)
	u8   family;		// network family
	u8   proto;		// protocol (sock.h: u8 older, u16 newer)
	u16  sport;		// source port
	u16  dport;		// destination port
	u32  saddr;		// source address
	struct in6_addr	saddr6;	// source address (IPv6)
	u32  daddr;		// destination address
        struct in6_addr	daddr6; // destination address (IPv6)
	u8   type;		// icmp type
	u8   code;		// icmp code
	u8   thesource;		// I am the one originating packet
};

#endif // BPFTRACKER_H_
