#!/bin/bash

# IP6_ADDR=fe80::a61f:72ff:fef5:9092;

[ -z "$4" ] && echo "args: <IP6> <PORT_INIT> <PORT_END> <INTERFACE>" && exit


IP6_ADDR=$1
PORT_INIT=$2
PORT_END=$3
INTERFACE=$4

ping -6 $IP6_ADDR -c 5;

MAC_ADDR=$( ip neigh | grep $IP6_ADDR | grep -o "[a-f0-9][a-f0-9]:[a-f0-9][a-f0-9]:[a-f0-9][a-f0-9]:[a-f0-9][a-f0-9]:[a-f0-9][a-f0-9]:[a-f0-9][a-f0-9]" | head -n1);

echo "address: $MAC_ADDR";

gcc -Wall -c message/message.c -w
gcc -Wall -c attack.c -w
gcc -o attack message.o attack.o -lpthread
rm *.o

./attack $IP6_ADDR $MAC_ADDR $PORT_INIT $PORT_END $INTERFACE
