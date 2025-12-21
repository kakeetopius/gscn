for i in {1..10}; do
docker run  -d --name netshoot-$i --network test nicolaka/netshoot sleep infinity
done
