# Connection Tracker / Firewall Rules Indicator

## Problems to solve

1. Log TCP, UDP and ICMP IPv4/IPv6 flows.
2. Understand the network traffic in a host (or firewall);
3. Create proper iptables (or nf_tables) rules;
4. Blame a firewall rule for a behavior (accept/deny);
5. Optimize firewall rules;

## Compiling (Ubuntu Way)

In order to compile it you will need the following Ubuntu packages installed:

 * pkg-config
 * libglib2.0-dev
 * libmnl-dev
 * libnetfilter-conntrack-dev
 * libelf-dev
 * clang-10 (or clang-11)
 * llvm-10 (or llvm-11)

In order to run it in another host you will need at least packages:

 * libglib2.0-0
 * libmnl0
 * libnfnetlink0
 * libnetfilter-conntrack3
 * libelf1

installed. Best way to do this is to rely on debian packaging build.

> If you want to manually compile the source code, take a look at debian.XXX/rules file and see the commands being used (and patches being applied).

### Using the correct **debian/** directory:

```
[rafaeldtinoco@example ~/devel/conntracker]$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 20.04.2 LTS
Release:	20.04
Codename:	focal
[rafaeldtinoco@example ~/devel/conntracker]$ cp -rfp debian.focal debian
```

### Installing the build dependencies


```
[rafaeldtinoco@example ~/devel/conntracker]$ apt-get build-dep .
Note, using directory '.' to get the build dependencies
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following NEW packages will be installed:
  dh-exec libmnl-dev libnetfilter-conntrack-dev libnetfilter-conntrack3 libnfnetlink-dev libnfnetlink0
0 upgraded, 6 newly installed, 0 to remove and 0 not upgraded.
Need to get 110 kB of archives.
After this operation, 509 kB of additional disk space will be used.
Do you want to continue? [Y/n] y
```

### Generating a source package

```
[rafaeldtinoco@example ~/devel/conntracker]$ dpkg-buildpackage -S -uc -us -sa
dpkg-buildpackage: info: source package conntracker
dpkg-buildpackage: info: source version 0.4-rc1ubuntu1~20.04.1
dpkg-buildpackage: info: source distribution focal
dpkg-buildpackage: info: source changed by Rafael David Tinoco <rafaeldtinoco@ubuntu.com>
...
dpkg-source: info: building conntracker in conntracker_0.4-rc1ubuntu1~20.04.1.tar.gz
dpkg-source: info: building conntracker in conntracker_0.4-rc1ubuntu1~20.04.1.dsc
 dpkg-genbuildinfo --build=source
 dpkg-genchanges -sa --build=source >../conntracker_0.4-rc1ubuntu1~20.04.1_source.changes
dpkg-genchanges: info: including full source code in upload
 dpkg-source --after-build .
dpkg-buildpackage: info: source-only upload: Debian-native package
 
```

### Generating a binary package

```
[rafaeldtinoco@example ~/devel/conntracker]$ dpkg-buildpackage -b -uc -us
dpkg-buildpackage: info: source package conntracker
dpkg-buildpackage: info: source version 0.4-rc1ubuntu1~20.04.1
dpkg-buildpackage: info: source distribution focal
dpkg-buildpackage: info: source changed by Rafael David Tinoco <rafaeldtinoco@ubuntu.com>
dpkg-buildpackage: info: host architecture amd64
...
dpkg-deb: building package 'conntracker' in '../conntracker_0.4-rc1ubuntu1~20.04.1_amd64.deb'.
dpkg-deb: building package 'conntracker-btf' in '../conntracker-btf_0.4-rc1ubuntu1~20.04.1_amd64.deb'.
dpkg-deb: building package 'conntracker-btf-hwe' in '../conntracker-btf-hwe_0.4-rc1ubuntu1~20.04.1_amd64.deb'.
...
dpkg-genchanges: info: binary-only upload (no source code included)
 dpkg-source --after-build .
dpkg-buildpackage: info: binary-only upload (no source included)
```

### Installing the binary package

```
[rafaeldtinoco@example ~/devel]$ ls -1 *.deb
conntracker_0.4-rc1ubuntu1~20.04.1_amd64.deb
conntracker-btf_0.4-rc1ubuntu1~20.04.1_amd64.deb
conntracker-btf-hwe_0.4-rc1ubuntu1~20.04.1_amd64.deb

[rafaeldtinoco@example ~/devel]$ sudo dpkg -i conntracker_0.4-rc1ubuntu1~20.04.1_amd64.deb conntracker-btf_0.4-rc1ubuntu1~20.04.1_amd64.deb
Selecting previously unselected package conntracker.
(Reading database ... 121725 files and directories currently installed.)
Preparing to unpack conntracker_0.4-rc1ubuntu1~20.04.1_amd64.deb ...
Unpacking conntracker (0.4-rc1ubuntu1~20.04.1) ...
Selecting previously unselected package conntracker-btf.
Preparing to unpack conntracker-btf_0.4-rc1ubuntu1~20.04.1_amd64.deb ...
Unpacking conntracker-btf (0.4-rc1ubuntu1~20.04.1) ...
Setting up conntracker (0.4-rc1ubuntu1~20.04.1) ...
Setting up conntracker-btf (0.4-rc1ubuntu1~20.04.1) ...
Processing triggers for man-db (2.9.1-1) ...
```

## Ubuntu Bionic and FocalSpecial Need for eBPF feature

Because Ubuntu kernels for Bionic and Focal, including [HWE kernels](https://wiki.ubuntu.com/Kernel/LTSEnablementStack), don't include [BTF information](https://github.com/rafaeldtinoco/portablebpf#portable-libbpf-based-ebpf-code-older-kernels), needed for libbpf to correctly calculate symbol relocations during runtime, conntracker needs either **conntracker-btf** or **conntracker-btf-hwe** packages installed as well, when running in Ubuntu Bionic or Focal (depending if you are using the regular Ubuntu kernel or the HWE one).

> If you are really interested on why the BTF file is needed, you will find all the information in the portablebpf repo, in the link above.

The packages **conntracker-btf** and **conntracker-btf-hwe** are not needed for Ubuntu Groovy and beyond so they don't exist for those versions.

### For Ubuntu Bionic

Using the regular kernel

```
$ uname -a
Linux bionic 4.15.0-142-generic #146-Ubuntu SMP Tue Apr 13 01:11:19 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

$ dpkg-query -W -f='${binary:Package}\t\t${Version}\n' conntracker conntracker-btf
conntracker     	0.4-rc1ubuntu1~18.04.1
conntracker-btf		0.4-rc1ubuntu1~18.04.1
```

or the HWE one

```
$ uname -a
Linux bionic 5.4.0-71-generic #79~18.04.1-Ubuntu SMP Thu Mar 25 05:45:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

$ apt-get install conntracker-btf-hwe
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following packages will be REMOVED:
  conntracker-btf
The following NEW packages will be installed:
  conntracker-btf-hwe
0 upgraded, 1 newly installed, 1 to remove and 0 not upgraded.
Need to get 1,026 kB of archives.
After this operation, 482 kB of additional disk space will be used.
Do you want to continue? [Y/n] y
...

$ dpkg-query -W -f='${binary:Package}\t\t${Version}\n' conntracker conntracker-btf-hwe
conntracker             0.4-rc1ubuntu1~18.04.1
conntracker-btf-hwe		0.4-rc1ubuntu1~18.04.1
```

### For Ubuntu Focal

Using the regular kernel

```
$ uname -a
Linux focal 5.4.0-72-generic #80-Ubuntu SMP Mon Apr 12 17:35:00 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

$ dpkg-query -W -f='${binary:Package}\t\t${Version}\n' conntracker conntracker-btf
conntracker		    0.4-rc1ubuntu1~20.04.1
conntracker-btf		0.4-rc1ubuntu1~20.04.1
```

or the HWE one

```
$ uname -a
Linux focal 5.8.0-49-generic #55~20.04.1-Ubuntu SMP Fri Mar 26 01:01:07 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

$ apt-get install conntracker-btf-hwe
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following packages will be REMOVED:
  conntracker-btf
The following NEW packages will be installed:
  conntracker-btf-hwe
0 upgraded, 1 newly installed, 1 to remove and 0 not upgraded.
Need to get 1,071 kB of archives.
After this operation, 177 kB of additional disk space will be used.
Do you want to continue? [Y/n] y

$ dpkg-query -W -f='${binary:Package}\t\t${Version}\n' conntracker conntracker-btf-hwe
conntracker             0.4-rc1ubuntu1~20.04.1
conntracker-btf-hwe		0.4-rc1ubuntu1~20.04.1
```

## Using the oficial project PPA

### Installing the PPA using add-apt-repository

This will install the Ubuntu PPA with stable conntracker:

```
$ sudo add-apt-repository -y ppa:conntracker/stable
Ign:1 http://ddebs.ubuntu.com focal InRelease
Get:2 http://ppa.launchpad.net/conntracker/stable/ubuntu focal InRelease [18.1 kB]
Ign:3 http://ddebs.ubuntu.com focal-updates InRelease
Hit:4 http://archive.ubuntu.com/ubuntu focal InRelease
Ign:5 http://ddebs.ubuntu.com focal-proposed InRelease
Hit:6 http://archive.ubuntu.com/ubuntu focal-updates InRelease
Hit:7 http://ddebs.ubuntu.com focal Release
Hit:8 http://archive.ubuntu.com/ubuntu focal-proposed InRelease
Hit:9 http://ddebs.ubuntu.com focal-updates Release
Hit:10 http://ddebs.ubuntu.com focal-proposed Release
Get:12 http://ppa.launchpad.net/conntracker/stable/ubuntu focal/main amd64 Packages [832 B]
Get:14 http://ppa.launchpad.net/conntracker/stable/ubuntu focal/main Translation-en [384 B]
Fetched 19.3 kB in 2s (8,931 B/s)
Reading package lists... Done

$ apt-get install conntracker conntracker-btf
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following NEW packages will be installed:
  conntracker conntracker-btf
0 upgraded, 2 newly installed, 0 to remove and 0 not upgraded.
Need to get 1,241 kB of archives.
After this operation, 4,836 kB of additional disk space will be used.
Get:1 http://ppa.launchpad.net/conntracker/stable/ubuntu focal/main amd64 conntracker amd64 0.4-rc1ubuntu1~20.04.1 [212 kB]
Get:2 http://ppa.launchpad.net/conntracker/stable/ubuntu focal/main amd64 conntracker-btf amd64 0.4-rc1ubuntu1~20.04.1 [1,029 kB]
Fetched 1,241 kB in 3s (473 kB/s)
Selecting previously unselected package conntracker.
(Reading database ... 129376 files and directories currently installed.)
Preparing to unpack .../conntracker_0.4-rc1ubuntu1~20.04.1_amd64.deb ...
Unpacking conntracker (0.4-rc1ubuntu1~20.04.1) ...
Selecting previously unselected package conntracker-btf.
Preparing to unpack .../conntracker-btf_0.4-rc1ubuntu1~20.04.1_amd64.deb ...
Unpacking conntracker-btf (0.4-rc1ubuntu1~20.04.1) ...
Setting up conntracker (0.4-rc1ubuntu1~20.04.1) ...
Setting up conntracker-btf (0.4-rc1ubuntu1~20.04.1) ...
Processing triggers for man-db (2.9.1-1) ...
```

### Installing the PPA manually

If you don't want to add the PPA through "add-apt-repository", you may add the repository key manually, update your sources.list file:

```
$ sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys AE4B4EA33C3DAE9E441E256C6B25BC6DF8365E53
$ echo "deb http://ppa.launchpad.net/conntracker/stable/ubuntu/ `lsb_release -cs` main" | sudo tee -a /etc/apt/sources.list
```

### Installing the binary packages from the PPA

And install the binary packages:

```
$ sudo apt-get update
$ sudo apt-get install conntracker
$ sudo apt-get install conntracker-bts # if needed
$ sudo conntracker -t -b -o -
...
```

## Using

Easily follow 2 steps:

1. Execute conntracker [options]:

```
$ sudo ./conntracker -h

Syntax: ./conntracker [options]

	[options]:

	-d: daemon mode        (syslog msgs, output file, kill pidfile)
	-f: foreground mode    (stdout msgs, output file, ctrl+c, default)

	-t: trace mode         (trace packets being tracked netfilter)
	-e: trace everything   (trace ALL packets passing through netfilter)
	-b: enable eBPF        (eBPF to catch TCP & UDP flows and their cmds)

	-o: -o file.out        (output file, default: /tmp/conntracker.log)
	    -o -               (standard output)

	1) defaults (no options):

	   a) ONLY packets from ALLOWED rules are tracked.
	   b) IPs, ports and protocols (flows) ARE LOGGED.
	   c) packets from DROPPED/REJECTED rules are NOT logged!

	2) -t (trace mode):

	   a) ONLY packets from ALLOWED rules are tracked.
	   b) IPs, ports and protocols (flows) ARE LOGGED.
	   c) packets from DROPPED/REJECTED rules are NOT logged!
	   d) each flow MIGHT show chains it has passed through (traces).

	3) -e (trace everything):

	   a) ONLY packets from ALLOWED rules are tracked.
	   b) IPs, ports and protocols (flows) ARE LOGGED.
	   c) -
	   d) each flow MIGHT show chains it has passed through (traces).
	   e) packets from DROPPED/REJECTED rules ARE logged!
	   f) WILL ALLOW tracking flows rejected by REJECT rules in place!
	   g) only works with -t (trace mode) enabled.

	3) -b (enable eBPF):

	   h) flows MIGHT show cmdline/pid/user responsible for them

	Note: -e option is recommended if REJECT/DROP rules are in place

Check https://rafaeldtinoco.github.io/conntracker/ for more info!
Check https://rafaeldtinoco.github.io/portablebpf/ for more info!
```

2. Read generated file (or output).

### Output File

The output of “conntracker” tool is self explanatory BUT some observations should be made:

  1. The output is **SORTED** by **PROTOCOL**, **SOURCE ADDR**, **DEST ADDR**, **SRC PORT** and **DEST PORTS** in given order. This is on purpose so the person executing it is able to observe IPs of a same subnet mask close enough to decide if future iptables rules should be HOST or SUBNET oriented.

  2. With '-t' option enabled, you may find under the lines indicating flows:<BR>
     **table: xxxx, chain: xxxx, type: xxxx, position: xxxx**<BR>
     "table": **raw, mangle, nat or filter**<BR>
     "chain": **PREROUTING, POSTROUTING, FORWARD, INPUT, OUTPUT**<BR>
     "type" : **policy, rule or return**<BR>

     **UNDERSTAND WHERE FLOW PASSED THROUGH WITH:**

  ![](docs/netfilter.png)
  
  3. With '-b' option enabled, you may find after the lines indicating flows:<BR>
     **cmdline,pid:xxxx,uid:username**<BR>
     It means conntracker was able to link observed flow with a running command.

## Example

```
$ sudo ./conntracker
Starting to capture conntrack events
Foreground mode...<Ctrl-C> or or SIG_TERM to end it.
Dumping internal data into: /tmp/conntracker.log
Finished capturing conntrack/ulog events
```

To check what was observed during the execution of the tool, and through which netfilter tables and rules that flow passed through, you just have to check generated file:

```
$ cat /tmp/conntracker.log
 TCPv4 [           0] src = 10.250.97.1 (port=2049) to dst = 10.250.97.151 (port=677) (-)
 TCPv4 [           1] src = 10.250.97.151 (port=677) to dst = 10.250.97.1 (port=2049) (-)
 TCPv4 [           2] src = 10.250.97.151 (port=46660) to dst = 192.168.200.114 (port=22) (-)
 TCPv4 [           3] src = 192.168.200.114 (port=22) to dst = 10.250.97.151 (port=46660) (-)
 UDPv4 [           0] src = 127.0.0.1 (port=8080) to dst = 127.0.0.1 (port=34091) (-)
 UDPv4 [           1] src = 127.0.0.1 (port=34091) to dst = 127.0.0.1 (port=8080) (-)
ICMPv4 [           0] src = 10.250.97.151 to dst = 8.8.4.4 (type=0 | code=0)
ICMPv4 [           1] src = 10.250.97.151 to dst = 8.8.8.8 (type=0 | code=0)
```

If you would like to see through which iptables rules those flows passed you can use '-t' option:

```
$ cat /tmp/conntracker.log
 TCPv4 [           0] src = 10.250.97.151 (port=46662) to dst = 192.168.200.114 (port=22) (-)
				table: mangle, chain: INPUT, type: policy
				table: mangle, chain: OUTPUT, type: policy
				table: mangle, chain: POSTROUTING, type: policy
				table: mangle, chain: PREROUTING, type: policy
				table: filter, chain: INPUT, type: policy
				table: filter, chain: OUTPUT, type: policy
 TCPv4 [           1] src = 192.168.200.114 (port=22) to dst = 10.250.97.151 (port=46662) (-)
				table: mangle, chain: INPUT, type: policy
				table: mangle, chain: OUTPUT, type: policy
				table: mangle, chain: POSTROUTING, type: policy
				table: mangle, chain: PREROUTING, type: policy
				table: filter, chain: INPUT, type: policy
				table: filter, chain: OUTPUT, type: policy
 UDPv4 [           0] src = 127.0.0.1 (port=57341) to dst = 127.0.0.1 (port=8080) (-)
 UDPv4 [           1] src = 127.0.0.1 (port=8080) to dst = 127.0.0.1 (port=57341) (-)
ICMPv4 [           0] src = 10.250.97.151 to dst = 8.8.4.4 (type=0 | code=0)
				table: mangle, chain: OUTPUT, type: policy
				table: mangle, chain: POSTROUTING, type: policy
				table: filter, chain: OUTPUT, type: policy
ICMPv4 [           1] src = 10.250.97.151 to dst = 8.8.8.8 (type=0 | code=0)
				table: mangle, chain: OUTPUT, type: policy
				table: mangle, chain: POSTROUTING, type: policy
				table: filter, chain: OUTPUT, type: policy
```

If you are even more curious and want to see which tasks created the local flows you can use '-b' option:

```
$ cat /tmp/conntracker.log
 TCPv4 [           0] src = 10.250.97.151 (port=46666) to dst = 192.168.200.114 (port=22) (ssh,pid:5057,uid:rafaeldtinoco)
				table: mangle, chain: INPUT, type: policy
				table: mangle, chain: OUTPUT, type: policy
				table: mangle, chain: POSTROUTING, type: policy
				table: mangle, chain: PREROUTING, type: policy
				table: filter, chain: INPUT, type: policy
				table: filter, chain: OUTPUT, type: policy
 TCPv4 [           1] src = 192.168.200.114 (port=22) to dst = 10.250.97.151 (port=46666) (ssh,pid:5057,uid:rafaeldtinoco)
				table: mangle, chain: INPUT, type: policy
				table: mangle, chain: OUTPUT, type: policy
				table: mangle, chain: POSTROUTING, type: policy
				table: mangle, chain: PREROUTING, type: policy
				table: filter, chain: INPUT, type: policy
				table: filter, chain: OUTPUT, type: policy
 UDPv4 [           0] src = 127.0.0.1 (port=46760) to dst = 127.0.0.1 (port=8080) (nc,pid:5042,uid:rafaeldtinoco)
 UDPv4 [           1] src = 127.0.0.1 (port=8080) to dst = 127.0.0.1 (port=46760) (nc,pid:5044,uid:rafaeldtinoco)
ICMPv4 [           0] src = 10.250.97.151 to dst = 8.8.4.4 (type=0 | code=0)
				table: mangle, chain: OUTPUT, type: policy
				table: mangle, chain: POSTROUTING, type: policy
				table: filter, chain: OUTPUT, type: policy
ICMPv4 [           1] src = 10.250.97.151 to dst = 8.8.8.8 (type=0 | code=0)
				table: mangle, chain: OUTPUT, type: policy
				table: mangle, chain: POSTROUTING, type: policy
				table: filter, chain: OUTPUT, type: policy
```

## Compatibility

The **conntracker** tool has been tested in Ubuntu Linux Groovy, Focal and Bionic using iptables.

** PAY ATTENTION **: Latest Ubuntus support both:

- iptables
- nf_tables

And whenever you execute "iptables" command you are actually, by default, executing the `nf_tables` based iptables (nft - in compatibility mode). Because this tool extensively uses iptables NFLOG & TRACE targets, and they are not compatible with `nf_tables`, it is **MANDATORY** that you use "iptables-legacy" for your firewall rules when using this tool. After discovering all the rules you want to create/keep/delete, you can go back to iptables-nft if you want.

## If you had to do everything by hand:

Let's say you don't have conntracker. To have something similar to what it provides, you would have to:

1. Make conntracker do the dirty job: map/unmap existing networking flows. 

```
*nat
:PREROUTING ACCEPT [190:33697]
:INPUT ACCEPT [65:12120]
:OUTPUT ACCEPT [404:50597]
:POSTROUTING ACCEPT [386:47349]
COMMIT
*raw
:PREROUTING ACCEPT [50:67129]
:OUTPUT ACCEPT [40:2928]
COMMIT
*mangle
:PREROUTING ACCEPT [242:293814]
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
:POSTROUTING ACCEPT [272:34654]
-A PREROUTING -m conntrack --ctdir REPLY -j NFLOG
-A INPUT -p udp -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -p tcp -j ACCEPT
-A FORWARD -m conntrack --ctstate INVALID,NEW,RELATED,ESTABLISHED,UNTRACKED,SNAT,DNAT -j NFLOG
-A FORWARD -p udp -j ACCEPT
-A FORWARD -p icmp -j ACCEPT
-A FORWARD -p ipv6-icmp -j ACCEPT
-A FORWARD -p tcp -j ACCEPT
-A OUTPUT -m conntrack --ctdir ORIGINAL -j NFLOG
-A OUTPUT -p udp -j ACCEPT
-A OUTPUT -p icmp -j ACCEPT
-A OUTPUT -p ipv6-icmp -j ACCEPT
-A OUTPUT -p tcp -j ACCEPT
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -p udp -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -p tcp -j ACCEPT
-A FORWARD -p udp -j ACCEPT
-A FORWARD -p icmp -j ACCEPT
-A FORWARD -p ipv6-icmp -j ACCEPT
-A FORWARD -p tcp -j ACCEPT
-A OUTPUT -p udp -j ACCEPT
-A OUTPUT -p icmp -j ACCEPT
-A OUTPUT -p ipv6-icmp -j ACCEPT
-A OUTPUT -p tcp -j ACCEPT
COMMIT
```

and to analyze the outcome:

```
# conntrack -E -e NEW

    [NEW] udp      17 30 src=192.168.100.251 dst=8.8.8.8 sport=53798 dport=53 [UNREPLIED] src=8.8.8.8 dst=192.168.200.2 sport=53 dport=53798
    [NEW] tcp      6 120 SYN_SENT src=192.168.100.118 dst=34.71.14.52 sport=40414 dport=443 [UNREPLIED] src=34.71.14.52 dst=192.168.200.2 sport=443 dport=40414
    [NEW] udp      17 30 src=192.168.100.251 dst=8.8.8.8 sport=33914 dport=53 [UNREPLIED] src=8.8.8.8 dst=192.168.200.2 sport=53 dport=33914
    [NEW] udp      17 30 src=192.168.100.251 dst=8.8.8.8 sport=41433 dport=53 [UNREPLIED] src=8.8.8.8 dst=192.168.200.2 sport=53 dport=41433
    [NEW] tcp      6 120 SYN_SENT src=192.168.100.118 dst=130.44.215.56 sport=40752 dport=80 [UNREPLIED] src=130.44.215.56 dst=192.168.200.2 sport=80 dport=40752
```

sorting all the output by protocol, source/destination addresses and source/destination port numbers. This would tell you what firewall rules would have to exist in your firewall to allow the flows (or block them).

But this is just half of the problem. If you want to understand why a specific flow is being blocked, you would have to trace that flow and check through which firewall rules that flow is flowing.

To trace all networking flows, you could:

```
# iptables -t raw -A PREROUTING -j TRACE
# iptables -t raw -A OUTPUT-j TRACE
# ip6tables -t raw -A PREROUTING -j TRACE
# ip6tables -t raw -A OUTPUT-j TRACE
```

and observe kmsg:

```
[ 1934.356558] TRACE: raw:OUTPUT:policy:2 IN= OUT=home SRC=192.168.100.203 DST=192.168.100.153 LEN=52 TOS=0x10 PREC=0x00 TTL=64 ID=26607 DF PROTO=TCP SPT=35310 DPT=22 SEQ=3621638314 ACK=4253970834 WINDOW=10016 RES=0x00 ACK URGP=0 OPT (0101080A938A85A902782273) UID=1000 GID=1000 
[ 1934.867689] TRACE: filter:OUTPUT:policy:1 IN= OUT=home SRC=192.168.100.203 DST=192.168.100.153 LEN=52 TOS=0x10 PREC=0x00 TTL=64 ID=26608 DF PROTO=TCP SPT=35310 DPT=22 SEQ=3621638314 ACK=4253970990 WINDOW=10016 RES=0x00 ACK URGP=0 OPT (0101080A938A87A802782470) UID=1000 GID=1000 
[ 1935.393687] TRACE: raw:OUTPUT:policy:2 IN= OUT=home SRC=192.168.100.203 DST=192.168.100.153 LEN=52 TOS=0x10 PREC=0x00 TTL=64 ID=26610 DF PROTO=TCP SPT=35310 DPT=22 SEQ=3621638406 ACK=4253971082 WINDOW=10016 RES=0x00 ACK URGP=0 OPT (0101080A938A89B60278267A) UID=1000 GID=1000 
[ 1935.687541] TRACE: filter:OUTPUT:policy:1 IN= OUT=home SRC=192.168.100.203 DST=192.168.100.153 LEN=52 TOS=0x10 PREC=0x00 TTL=64 ID=26611 DF PROTO=TCP SPT=35310 DPT=22 SEQ=3621638406 ACK=4253971238 WINDOW=10016 RES=0x00 ACK URGP=0 OPT (0101080A938A8ADC0278279B) UID=1000 GID=1000 
```

but then you would add too much work to your netfilter code, making kernel to inform about all flows being tracked by conntracker, for example. Correct thing to do would be to trace each flow for a specific amount of time, once its first seen, and then stop it. 

The **conntracker** tool does all that automatically.
