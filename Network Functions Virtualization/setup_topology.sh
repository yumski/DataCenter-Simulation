#!/bin/bash

# Setup the topology and endpoints here.
sudo docker build -f Dockerfile.endpoint -t endpoint:latest .

echo "Creating virtual bridge: ovs-br1"
sudo ovs-vsctl add-br ovs-br1
sudo ovs-vsctl set-controller ovs-br1 tcp:127.0.0.1:6633
sudo ovs-vsctl set-fail-mode ovs-br1 secure

echo "Creating virtual bridge: ovs-br2"
sudo ovs-vsctl add-br ovs-br2
sudo ovs-vsctl set-controller ovs-br2 tcp:127.0.0.1:6633
sudo ovs-vsctl set-fail-mode ovs-br2 secure

sudo ovs-vsctl set bridge ovs-br1 other-config:datapath-id=0000000000000001
sudo ovs-vsctl set bridge ovs-br2 other-config:datapath-id=0000000000000002

# https://mail.openvswitch.org/pipermail/ovs-discuss/2014-May/033723.html
sudo ovs-vsctl add-port ovs-br1 patch1 \
    -- set interface patch1 type=patch options:peer=patch2 \
    -- add-port ovs-br2 patch2 \
    -- set interface patch2 type=patch options:peer=patch1

echo "Starting host: src1"
sudo docker run -d --privileged --name=src1 --net=none endpoint:latest tail -f /dev/null

echo "Starting host: src2"
sudo docker run -d --privileged --name=src2 --net=none endpoint:latest tail -f /dev/null

echo "Starting host: dst1"
sudo docker run -d --privileged --name=dst1 --net=none endpoint:latest tail -f /dev/null

echo "Starting host: dst2"
sudo docker run -d --privileged --name=dst2 --net=none endpoint:latest tail -f /dev/null

echo "Attaching eth0 to bridge for host: src1"
sudo ovs-docker add-port ovs-br1 eth0 src1 --ipaddress="192.168.1.2/24" --macaddress="00:00:00:00:00:01"

echo "Attaching eth0 to bridge for host: src2"
sudo ovs-docker add-port ovs-br1 eth0 src2 --ipaddress="192.168.1.3/24" --macaddress="00:00:00:00:00:02"

echo "Attaching eth0 to bridge for host: dst1"
sudo ovs-docker add-port ovs-br2 eth0 dst1 --ipaddress="143.12.131.92/24" --macaddress="00:00:00:00:01:01"

echo "Attaching eth0 to bridge for host: dst2"
sudo ovs-docker add-port ovs-br2 eth0 dst2 --ipaddress="143.12.131.93/24" --macaddress="00:00:00:00:01:02"

sudo docker exec src1 ip route add 143.12.131.0/24 dev eth0
sudo docker exec src2 ip route add 143.12.131.0/24 dev eth0

sudo docker exec dst1 ip route add 192.168.1.0/24 dev eth0
sudo docker exec dst2 ip route add 192.168.1.0/24 dev eth0


