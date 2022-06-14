#include <stdio.h>
#include <stdlib.h>
#include "message/message.h"
#include "pthread.h"
int main(int argc, char **argv)
{
    char interface[40];
    int dst_port; 
    if (argc > 2)
    {    
	strcpy(interface, argv[1]);
    	dst_port = atoi(argv[2]);
    }
    else
    {
        strcpy(interface, "wlp0s20f3");
    	dst_port = atoi("8000");
    }

    printf("%d\n", dst_port);

    
    
    pthread_t th_recv;
    pthread_create(&th_recv, NULL, recvTCP, NULL);
    sleep(1);
    
    
    
    
    
    char *dst_addr = malloc(sizeof(char*) * INET6_ADDRSTRLEN);
    dst_addr = "2804:14d:4c89:8dd2:d166:993:f2f:b5bb";
    struct message msg = {"2804:14d:4c89:8dd2:d166:993:f2f:b5bb", (uint16_t)dst_port, interface};
    printf("ready to fly\n");
    sendTcp(msg, FIN_FLAG);

    pthread_join(th_recv, NULL);
    return 1;

}
