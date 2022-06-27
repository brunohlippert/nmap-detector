rm detector
gcc -Wall -c message/message.c -w
gcc -Wall -c detector.c -w

gcc -o detector message.o detector.o -lpthread
rm *.o

sudo ./detector wlp0s20f3
