#!/bin/bash

sudo docker stop src1
sudo docker stop src2
sudo docker stop dst1
sudo docker stop dst2

sudo docker stop nat1
sudo docker stop nat2
sudo docker stop nat3
sudo docker stop nat4

sudo docker stop fw1
sudo docker stop fw2
sudo docker stop fw3

sudo docker rm src1
sudo docker rm src2
sudo docker rm dst1
sudo docker rm dst2

sudo docker rm nat1
sudo docker rm nat2
sudo docker rm nat3
sudo docker rm nat4

sudo docker rm fw1
sudo docker rm fw2
sudo docker rm fw3

sudo ovs-vsctl del-br ovs-br1
sudo ovs-vsctl del-br ovs-br2