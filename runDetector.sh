rm detector
gcc -Wall -c message/message.c -w
gcc -Wall -c detector.c -w
gcc -Wall -c attack_statemachines.c -w

gcc -o detector message.o detector.o attack_statemachines.o -lpthread
rm *.o

sudo ./detector enp4s0