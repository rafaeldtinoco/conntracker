#!/bin/bash

./tools/wipe.sh

for iptable in iptables ip6tables; do

	iptables="sudo $iptable -w"

	for table in filter mangle; do

	$iptables -t $table -A OUTPUT --proto udp -j ACCEPT
	$iptables -t $table -A OUTPUT --proto icmp -j ACCEPT
	$iptables -t $table -A OUTPUT --proto icmpv6 -j ACCEPT
	$iptables -t $table -A OUTPUT --proto tcp -j ACCEPT

	$iptables -t $table -A INPUT --proto udp -j ACCEPT
	$iptables -t $table -A INPUT --proto icmp -j ACCEPT
	$iptables -t $table -A INPUT --proto icmpv6 -j ACCEPT
	$iptables -t $table -A INPUT --proto tcp -j ACCEPT

	$iptables -t $table -A FORWARD --proto udp -j ACCEPT
	$iptables -t $table -A FORWARD --proto icmp -j ACCEPT
	$iptables -t $table -A FORWARD --proto icmpv6 -j ACCEPT
	$iptables -t $table -A FORWARD --proto tcp -j ACCEPT

	$iptables -t $table -P OUTPUT DROP
	$iptables -t $table -P INPUT DROP
	$iptables -t $table -P FORWARD DROP

	done
done

if [ -f /sbin/iptables-legacy ]; then

	for iptable in iptables-legacy ip6tables-legacy; do

		iptables="sudo $iptable -w"

		for table in filter mangle; do

		$iptables -t $table -P OUTPUT DROP
		$iptables -t $table -P INPUT DROP
		$iptables -t $table -P FORWARD DROP

		done
	done
fi
