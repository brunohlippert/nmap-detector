#include <stdio.h>
#include <stdlib.h>
#include "message/message.h"
#include "pthread.h"
int main(int argc, char **argv)
{
    char interface[40], dst_address[INET6_ADDRSTRLEN];
    uint16_t dst_port;

    if (argc > 2)
    {
        strcpy(interface, argv[1]);
        dst_port = atoi(argv[2]);
    }
    else
    {
        strcpy(interface, "enp1s0");
        dst_port = atoi("10");
    }

    strcpy(dst_address, "2804:d51:4330:7d00:502d:6bff:fef8:cf79");

    struct message msg = {dst_address, dst_port, interface};

    pthread_t th_recv;
    pthread_create(&th_recv, NULL, recvTCP, dst_address);

    sendTcp(msg, FIN_FLAG);

    pthread_join(th_recv, NULL);
    return 1;
}
