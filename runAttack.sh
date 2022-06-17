#!/bin/bash


[ -z "$4" ] && echo "args: <IP6> <PORT_INIT> <PORT_END> <INTERFACE>" && exit

IP6_ADDR=$1
PORT_INIT=$2
PORT_END=$3
INTERFACE=$4

echo "Buscando endereço MAC..." & ping -6 $IP6_ADDR -q -c 5;

MAC_ADDR=$( ip neigh | grep $IP6_ADDR | grep -o "[a-f0-9][a-f0-9]:[a-f0-9][a-f0-9]:[a-f0-9][a-f0-9]:[a-f0-9][a-f0-9]:[a-f0-9][a-f0-9]:[a-f0-9][a-f0-9]" | head -n1);

echo "\n    IPV6:  $IP6_ADDR";
echo "       MAC:  $MAC_ADDR";
echo "RANGE PORT:  [$PORT_INIT, $PORT_END]";
echo " INTERFACE:  $INTERFACE\n\n";

gcc -Wall -c message/message.c -w
gcc -Wall -c attack.c -w
gcc -o attack message.o attack.o -lpthread
rm *.o

./attack $IP6_ADDR $MAC_ADDR $PORT_INIT $PORT_END $INTERFACE
