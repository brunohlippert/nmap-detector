#include <stdio.h>
#include <stdlib.h>
#include "message/message.h"
#include "pthread.h"


// Tipos de ataques
#define TCP_CONNECT 1
#define TCP_HALF_OPENING 2
#define TCP_FIN 3
#define TCP_FIN_PUSH_URG 4


void stringToMAC(char *mac_str, uint8_t *mac_addr){
	int curr_index = 0;
	int hex_index = 0;
	char *hex_str = malloc(sizeof(char*) * 2);
	for(int i = 0; i < 17; i++){
		if (mac_str[i] == ':'){
			mac_addr[curr_index] = (uint8_t)strtol(hex_str, NULL, 16);
			curr_index += 1;
			hex_index = 0;
			hex_str[0] = '0';
			hex_str[1] = '1';
		}
		else{
			hex_str[hex_index] = mac_str[i];
			hex_index++;
		}
			
	}
	mac_addr[curr_index] = (uint8_t)strtol(hex_str, NULL, 16);
	free(hex_str);

}

int main(int argc, char **argv)
{
    int attack_type;
    struct message msg;
    if (argc > 5)
    {
        strcpy(msg.dst_addr, argv[1]);
	    stringToMAC(argv[2], &msg.dst_mac);
	    msg.inital_port = strtol(argv[3], NULL, 10);
        msg.final_port = strtol(argv[4], NULL, 10);
        strcpy(msg.interface, argv[5]);
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
    printf("4 - TCP FIN/PUSH/URG\n");
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
    case TCP_FIN_PUSH_URG:
        tcpFinPushUrgAttack(msg);
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
    struct recv_msg recvMsg;

    int i = 0;
    for (int portaAtual = msg.inital_port; portaAtual < msg.final_port + 1; portaAtual++)
    {
        pthread_t th_recv;
        strcpy(recvMsg.ds_addr, msg.dst_addr);
        recvMsg.s_port = portaAtual;
        pthread_create(&th_recv, NULL, recvTCP, (void*)&recvMsg);
        
        sendTcp(msg.dst_addr, msg.dst_mac, portaAtual, SYN_FLAG, msg.interface);

        void *flag;
        pthread_join(th_recv, &flag);

        if ((int)flag == SYN_ACK_FLAG)
        //if(((uint8_t)flag & ACK_FLAG == ACK_FLAG) && ((uint8_t)flag & SYN_FLAG == SYN_FLAG))
	{
            ports[i++] = 1; // Aberta
            sendTcp(msg.dst_addr, msg.dst_mac, portaAtual, ACK_FLAG, msg.interface);
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
    struct recv_msg recvMsg;

    int i = 0;
    for (int portaAtual = msg.inital_port; portaAtual < msg.final_port + 1; portaAtual++)
    {
        pthread_t th_recv;
        strcpy(recvMsg.ds_addr, msg.dst_addr);
        recvMsg.s_port = portaAtual;
        pthread_create(&th_recv, NULL, recvTCP, (void*)&recvMsg);
        
        sendTcp(msg.dst_addr, msg.dst_mac, portaAtual, SYN_FLAG, msg.interface);

        void *flag;
        pthread_join(th_recv, &flag);

        if ((int)flag == SYN_ACK_FLAG)
        //if( ((uint8_t)flag & ACK_FLAG == ACK_FLAG) && ((uint8_t)flag & SYN_FLAG == SYN_FLAG) ) 
	{
            ports[i++] = 1; // Aberta
            sendTcp(msg.dst_addr, msg.dst_mac, portaAtual, RST_FLAG, msg.interface);
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
    printf("Iniciando ataque FIN ACK...\n");

    int numPorts = msg.final_port - msg.inital_port;
    int *ports = malloc(sizeof(int) * numPorts);
    
    struct recv_msg recvMsg;

    int i = 0;
    for (int portaAtual = msg.inital_port; portaAtual < msg.final_port + 1; portaAtual++)
    {
        pthread_t th_recv;
        strcpy(recvMsg.ds_addr, msg.dst_addr);
        recvMsg.s_port = portaAtual;
        pthread_create(&th_recv, NULL, recvTCP, (void*)&recvMsg);
        
        sendTcp(msg.dst_addr, msg.dst_mac, portaAtual, FIN_FLAG, msg.interface);

        void *flag;
        pthread_join(th_recv, &flag);

        if ((int)flag == RST_ACK_FLAG)
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


void tcpFinPushUrgAttack(struct message msg)
{
    printf("Iniciando ataque TCP FIN/PUSH/URG...\n");

    int numPorts = msg.final_port - msg.inital_port;
    int *ports = malloc(sizeof(int) * numPorts);
    struct recv_msg recvMsg;

    int i = 0;
    for (int portaAtual = msg.inital_port; portaAtual < msg.final_port + 1; portaAtual++)
    {
        pthread_t th_recv;
        strcpy(recvMsg.ds_addr, msg.dst_addr);
        recvMsg.s_port = portaAtual;
        pthread_create(&th_recv, NULL, recvTCP, (void*)&recvMsg);
        
        sendTcp(msg.dst_addr, msg.dst_mac, portaAtual, FIN_PUSH_URG_FLAG,msg.interface);

        void *flag;
        pthread_join(th_recv, &flag);

        if ((int)flag == RST_ACK_FLAG)
        {
            ports[i++] = 0; // FECHADA
        }
        else
        {
            ports[i++] = 1; // ABERTA
        }
    }
    printResultado(ports, numPorts, msg.inital_port);

    printf("FIN/PUSH/URG finalizado com successo!\n");
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
