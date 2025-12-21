#!/usr/bin/env bash
make() {
    for i in {1..10}; do
    docker run  -d --name netshoot-$i --network test nicolaka/netshoot sleep infinity
    done
}

remove() {
    docker rm -f $(docker ps -q --filter name=netshoot-)
}

if [ "$1" == "remove" ]; then
    remove
else
    make
fi


