gcc -Wall -c message/message.c -w
gcc -Wall -c attack.c -w
gcc -o attack message.o attack.o -lpthread
rm *.o

./attack

