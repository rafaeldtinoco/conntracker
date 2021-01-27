#!/bin/bash

iptables="sudo iptables -w"
ip6tables="sudo ip6tables -w"

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
