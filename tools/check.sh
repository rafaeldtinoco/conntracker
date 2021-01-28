#!/bin/bash

if [ -f /sbin/iptables-legacy ]; then
	iptable="iptables-legacy"
	ip6table="ip6tables-legacy"
else
	iptable="iptables"
	ip6table="ip6tables"
fi

iptables="sudo $iptable -w"
ip6tables="sudo $ip6table -w"

for table in raw filter nat mangle
do
	echo
	echo ---- IPv4: $table
	echo
	$iptables -t $table -L -n --line-numbers
done

for table in raw filter nat mangle
do
	echo
	echo ---- IPv6: $table
	echo
	$ip6tables -t $table -L -n --line-numbers
done
