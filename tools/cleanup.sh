#!/bin/bash

iptables="sudo iptables -w"
ip6tables="sudo ip6tables -w"

for _ in $(seq 1 5)
do

# ipv4

$iptables -t filter -D CONNTRACKER -m conntrack --ctstate  NEW,ESTABLISHED,RELATED,UNTRACKED,INVALID,SNAT,DNAT -j RETURN
$iptables -t mangle -D CONNTRACKER -m conntrack --ctstate  NEW,ESTABLISHED,RELATED,UNTRACKED,INVALID,SNAT,DNAT -j RETURN
$iptables -t nat -D CONNTRACKER -m conntrack --ctstate  NEW,ESTABLISHED,RELATED,UNTRACKED,INVALID,SNAT,DNAT -j RETURN
$iptables -t filter -D INPUT -j CONNTRACKER
$iptables -t filter -D FORWARD -j CONNTRACKER
$iptables -t filter -D OUTPUT -j CONNTRACKER
$iptables -t mangle -D PREROUTING -j CONNTRACKER
$iptables -t mangle -D INPUT -j CONNTRACKER
$iptables -t mangle -D FORWARD -j CONNTRACKER
$iptables -t mangle -D OUTPUT -j CONNTRACKER
$iptables -t mangle -D POSTROUTING -j CONNTRACKER
$iptables -t nat -D PREROUTING -j CONNTRACKER
$iptables -t nat -D INPUT -j CONNTRACKER
$iptables -t nat -D OUTPUT -j CONNTRACKER
$iptables -t nat -D POSTROUTING -j CONNTRACKER
$iptables -t filter -X CONNTRACKER
$iptables -t mangle -X CONNTRACKER
$iptables -t nat -X CONNTRACKER

# ipv6

$ip6tables -t filter -D CONNTRACKER -m conntrack --ctstate  NEW,ESTABLISHED,RELATED,UNTRACKED,INVALID,SNAT,DNAT -j RETURN
$ip6tables -t mangle -D CONNTRACKER -m conntrack --ctstate  NEW,ESTABLISHED,RELATED,UNTRACKED,INVALID,SNAT,DNAT -j RETURN
$ip6tables -t nat -D CONNTRACKER -m conntrack --ctstate  NEW,ESTABLISHED,RELATED,UNTRACKED,INVALID,SNAT,DNAT -j RETURN
$ip6tables -t filter -D INPUT -j CONNTRACKER
$ip6tables -t filter -D FORWARD -j CONNTRACKER
$ip6tables -t filter -D OUTPUT -j CONNTRACKER
$ip6tables -t mangle -D PREROUTING -j CONNTRACKER
$ip6tables -t mangle -D INPUT -j CONNTRACKER
$ip6tables -t mangle -D FORWARD -j CONNTRACKER
$ip6tables -t mangle -D OUTPUT -j CONNTRACKER
$ip6tables -t mangle -D POSTROUTING -j CONNTRACKER
$ip6tables -t nat -D PREROUTING -j CONNTRACKER
$ip6tables -t nat -D INPUT -j CONNTRACKER
$ip6tables -t nat -D OUTPUT -j CONNTRACKER
$ip6tables -t nat -D POSTROUTING -j CONNTRACKER
$ip6tables -t filter -X CONNTRACKER
$ip6tables -t mangle -X CONNTRACKER
$ip6tables -t nat -X CONNTRACKER

done
