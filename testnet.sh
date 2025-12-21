#!/usr/bin/env bash
make() {
    docker network create --subnet 172.16.22.0/24 testnet
    for i in {1..10}; do
    docker run  -d --name alpine-$i --network testnet alpine:latest sleep infinity
    done
    echo -e "\nNetwork address of test network is 172.16.22.0/24"
    echo "Run testnet.sh remove to clean up"
}

remove() {
    toremove=$(docker ps -q --filter name=alpine-)
    if [ -n "$toremove" ]; then
	docker rm -f $toremove
    fi
    toremove=$(docker network ls -q --filter name=testnet)
    if [ -n "$toremove" ]; then
	docker network rm "$toremove"
    fi
}

case "$1" in 
    "remove")
	remove
	;;
    "")
	make
	;;
    *)
	echo "Unknown command: $1. To make a test network run with no arguments"
	;;
esac

