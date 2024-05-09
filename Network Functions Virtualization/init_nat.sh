#!/bin/bash

sudo docker build -f Dockerfile.nf -t nf:latest .

echo "Starting nat: $1"
sudo docker run -d --privileged --name=$1 --net=none nf:latest tail -f /dev/null

echo "Connecting $1 to br2 with eth0 ip $2/24"
sudo ovs-docker add-port ovs-br2 eth0 $1 --ipaddress=$2/24 --macaddress=$4

echo "Connecting $1 to br2 with eth1 ip $3/24"
sudo ovs-docker add-port ovs-br2 eth1 $1 --ipaddress=$3/24 --macaddress=$5

sudo docker exec $1 sysctl net.ipv4.ip_forward=1

sudo docker exec $1 iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
sudo docker exec $1 iptables -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo docker exec $1 iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
