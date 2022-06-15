#include <net/ethernet.h>
#include <netinet/in.h>	

// Define some constants.
#define ETH_HDRLEN 14 // Ethernet header length
#define IP6_HDRLEN 40 // IPv6 header length
#define TCP_HDRLEN 20 // TCP header length, excludes options data

// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header)
#define FRAME_LENGTH  ETH_HDRLEN + IP6_HDRLEN + TCP_HDRLEN + 1000

// Define TCP Useful flags
#define FIN_FLAG 0x01
#define SYN_FLAG 0x02
#define RST_FLAG 0x04
#define ACK_FLAG 0x10
#define SYN_ACK_FLAG 0x12
#define RST_ACK_FLAG 0x14

#define NO_RESPONSE 0x999

// Tipos de ataques
#define TCP_CONNECT 1
#define TCP_HALF_OPENING 2
#define TCP_FIN 3
#define SYN_ACK 4

// Controle de timeout para thread que recebe tcp
#define TIME_OUT_SECONDS 8

struct message
{
    char dst_addr[INET6_ADDRSTRLEN];
    int inital_port;
    int final_port;
    char interface[40];
};


void *recvTCP();
int sendTcp(char *dst_ip, int port, uint8_t tcp_flag, char * interface);

int openRawSocket(char *interface);
uint8_t *getMacFromInterface(char *interface, int socketDescriptor);
struct sockaddr_ll getInterfaceDevice(char *interface);
struct ip6_hdr getIPV6Header(char * src_ip, char * dst_ip);
struct tcphdr getTCPHeader(struct ip6_hdr iphdr, uint16_t dst_port, uint8_t tcp_flag);
uint8_t *getEthernetFrame(char *src_mac, char *dst_mac, struct ip6_hdr iphdr, struct tcphdr tcphdr);
void sendEthernetFrame(uint8_t *ether_frame, int socketDescriptor, struct sockaddr_ll device);

uint16_t checksum(uint16_t *, int);
uint16_t tcp6_checksum(struct ip6_hdr, struct tcphdr);
