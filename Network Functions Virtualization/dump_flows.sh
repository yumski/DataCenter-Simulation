#!/bin/bash

sudo ovs-ofctl -O OpenFlow13 dump-flows $1 | grep -E $2