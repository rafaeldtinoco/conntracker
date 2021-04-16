#!/bin/bash

current=$(pwd)

[[ ! -d ebpf/libbpf ]] && exit 1

if [[ $1 == clean ]]
then
	cd ebpf/libbpf && {
		git clean -fd
		git reset --hard
	}
fi

if [[ "$1" == "ubuntu" ]]
then
	cd ebpf/libbpf && {
		git clean -fd
		git reset --hard
		# only here because of the kprobe names optimization handling
		patch -p1 < ../patches/libbpf-introduce-legacy-kprobe-events-support.patch
	}
fi

cd $current
