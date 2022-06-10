#include <stdio.h>
#include <stdlib.h>
#include "message/message.h"

int main(int argc, char **argv)
{
    char interface[40];

    if (argc > 1)
        strcpy(interface, argv[1]);
    else
        strcpy(interface, "wlp2s0");

    struct message msg = {"fe80::5e26:aff:fe6e:aa88", interface};

    sendTcp(msg);
}