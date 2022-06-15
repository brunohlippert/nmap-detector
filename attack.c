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
        strcpy(interface, "eth0");
        dst_port = atoi("11");
    }

    strcpy(dst_address, "fe80::200:ff:feaa:1");

    struct message msg = {dst_address, dst_port, interface};

    pthread_t th_recv;
    pthread_create(&th_recv, NULL, recvTCP, dst_address);

    sleep(1);
    sendTcp(msg, FIN_FLAG);

    pthread_join(th_recv, NULL);
    return 1;
}
