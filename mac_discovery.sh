#!/bin/bash

IP6_ADDR=2804:14d:4c89:8dd2:3819:1f6e:3e5d:c6aa;

ping -6 $IP6_ADDR -c 10;

MAC_ADDR=$( ip neigh | grep $IP6_ADDR | grep -o "[a-f0-9][a-f0-9]:[a-f0-9][a-f0-9]:[a-f0-9][a-f0-9]:[a-f0-9][a-f0-9]:[a-f0-9][a-f0-9]:[a-f0-9][a-f0-9]" | head -n1);

echo "address: $MAC_ADDR";

