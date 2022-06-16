#include <stdio.h>
#include <stdlib.h>
#include "message/message.h"
#include "pthread.h"

int main(int argc, char **argv)
{
    int attack_type;
    struct message msg;
    if (argc > 4)
    {
        strcpy(msg.dst_addr, argv[1]);
        msg.inital_port = strtol(argv[2], NULL, 10);
        msg.final_port = strtol(argv[3], NULL, 10);
        strcpy(msg.interface, argv[4]);
    }
    else
    {
	perror("Numero invalido de argumentos precisa de 4");
    }

    if (msg.inital_port > msg.final_port)
    {
        perror("A porta inicial nao pode ser maior que a final\n");
    }

    printf("Selecione o ataque desejado:\n");
    printf("1 - TCP connect\n");
    printf("2 - TCP half-opening\n");
    printf("3 - TCP FIN\n");
    printf("4 - SYN/ACK\n");
    scanf("%d", &attack_type);

    switch (attack_type)
    {
    case TCP_CONNECT:
        tcpConnectAttack(msg);
        break;
    case TCP_HALF_OPENING:
        tcpHalfOpeningAttack(msg);
        break;
    case TCP_FIN:
        tcpFinAttack(msg);
        break;
    case SYN_ACK:
        tcpSynAckAttack(msg);
        break;
    default:
        perror("Ataque invalido\n");
    }

    return 1;
}

void tcpConnectAttack(struct message msg)
{
    printf("Iniciando ataque TCP CONNECT...\n");

    int numPorts = msg.final_port - msg.inital_port;
    int *ports = malloc(sizeof(int) * numPorts);

    int i = 0;
    for (int portaAtual = msg.inital_port; portaAtual < msg.final_port + 1; portaAtual++)
    {
        pthread_t th_recv;
        pthread_create(&th_recv, NULL, recvTCP, msg.dst_addr);
        sendTcp(msg.dst_addr, portaAtual, SYN_FLAG, msg.interface);

        void *flag;
        pthread_join(th_recv, &flag);

        //if ((int)flag == ACK_FLAG || (int)flag == SYN_ACK_FLAG)
        if(((uint8_t)flag & ACK_FLAG == ACK_FLAG) && ((uint8_t)flag & SYN_FLAG == SYN_FLAG))
	{
            ports[i++] = 1; // Aberta
            sendTcp(msg.dst_addr, portaAtual, ACK_FLAG, msg.interface);
        }
        else
        {
            ports[i++] = 0; // Fechada
        }
    }
    printResultado(ports, numPorts, msg.inital_port);

    printf("TCP CONNECT finalizado com successo!\n");
    free(ports);
}

void tcpHalfOpeningAttack(struct message msg)
{
    printf("Iniciando ataque TCP HALF OPENING...\n");

    int numPorts = msg.final_port - msg.inital_port;
    int *ports = malloc(sizeof(int) * numPorts);

    int i = 0;
    for (int portaAtual = msg.inital_port; portaAtual < msg.final_port + 1; portaAtual++)
    {
        pthread_t th_recv;
        pthread_create(&th_recv, NULL, recvTCP, msg.dst_addr);
        sendTcp(msg.dst_addr, portaAtual, SYN_FLAG, msg.interface);

        void *flag;
        pthread_join(th_recv, &flag);

        //if ((int)flag == ACK_FLAG || (int)flag == SYN_ACK_FLAG)
        if( ((uint8_t)flag & ACK_FLAG == ACK_FLAG) && ((uint8_t)flag & FIN_FLAG == FIN_FLAG) ) 
	{
            ports[i++] = 1; // Aberta
            sendTcp(msg.dst_addr, portaAtual, RST_FLAG, msg.interface);
        }
        else
        {
            ports[i++] = 0; // Fechada
        }
    }
    printResultado(ports, numPorts, msg.inital_port);

    printf("TCP HALF OPENING finalizado com successo!\n");
    free(ports);
}

void tcpFinAttack(struct message msg)
{
    printf("Iniciando ataque SYN ACK...\n");

    int numPorts = msg.final_port - msg.inital_port;
    int *ports = malloc(sizeof(int) * numPorts);

    int i = 0;
    for (int portaAtual = msg.inital_port; portaAtual < msg.final_port + 1; portaAtual++)
    {
        pthread_t th_recv;
        pthread_create(&th_recv, NULL, recvTCP, msg.dst_addr);
        sendTcp(msg.dst_addr, portaAtual, FIN_FLAG, msg.interface);

        void *flag;
        pthread_join(th_recv, &flag);

        //if ((int)flag == RST_ACK_FLAG || (int)flag == RST_FLAG)
        if( ((uint8_t)flag & ACK_FLAG == ACK_FLAG) && ((uint8_t)flag & RST_FLAG == RST_FLAG) )
	{
            ports[i++] = 0; // Fechada
        }
        else
        {
            ports[i++] = 1; // Aberta
        }
    }
    printResultado(ports, numPorts, msg.inital_port);

    printf("TCP FIN finalizado com successo!\n");
    free(ports);
}

void tcpSynAckAttack(struct message msg)
{
    printf("Iniciando ataque TCP FIN...\n");

    int numPorts = msg.final_port - msg.inital_port;
    int *ports = malloc(sizeof(int) * numPorts);

    int i = 0;
    for (int portaAtual = msg.inital_port; portaAtual < msg.final_port + 1; portaAtual++)
    {
        pthread_t th_recv;
        pthread_create(&th_recv, NULL, recvTCP, msg.dst_addr);
        sendTcp(msg.dst_addr, portaAtual, SYN_ACK_FLAG, msg.interface);

        void *flag;
        pthread_join(th_recv, &flag);

        if ((int)flag == RST_FLAG)
        {
            ports[i++] = 1; // ABERTA
        }
        else
        {
            ports[i++] = 0; // FECHADA
        }
    }
    printResultado(ports, numPorts, msg.inital_port);

    printf("SYN ACK finalizado com successo!\n");
    free(ports);
}

void printResultado(int *ports, int numPorts, int portaInicial)
{
    for (int i = 0; i < numPorts; i++)
    {
        if (ports[i] == 1)
            printf("Porta %d está aberta!\n", i + portaInicial);
    }
}
