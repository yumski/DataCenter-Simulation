#!/bin/bash

sudo docker build -f Dockerfile.nf -t nf:latest .

echo "Starting fw: $1"
sudo docker run -d --privileged --name=$1 --net=none nf:latest tail -f /dev/null

echo "Attaching mac addresses to bridge for nf: $1"
sudo ovs-docker add-port ovs-br1 eth0 $1 --macaddress=$4
sudo ovs-docker add-port ovs-br1 eth1 $1 --macaddress=$5

sudo docker exec $1 ip route add $2 dev eth0
sudo docker exec $1 ip route add $3 dev eth1

sudo docker exec $1 sysctl net.ipv4.ip_forward=1

sudo docker exec $1 iptables -A FORWARD -i eth1 -p tcp --destination-port 22 -j DROP
sudo docker exec $1 iptables -A FORWARD -i eth1 -p tcp --destination-port 22 -j DROP