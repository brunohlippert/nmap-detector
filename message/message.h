#include <net/ethernet.h>
#include <netinet/in.h>	

// Define some constants.
#define ETH_HDRLEN 14 // Ethernet header length
#define IP6_HDRLEN 40 // IPv6 header length
#define TCP_HDRLEN 20 // TCP header length, excludes options data

// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header)
#define FRAME_LENGTH  ETH_HDRLEN + IP6_HDRLEN + TCP_HDRLEN + 1000

// Define TCP Useful flags
#define SYN_FLAG 0x02
#define FIN_FLAG 0x01
#define ACK_FLAG 0x10

struct message
{
    char *dst_addr;
    uint16_t dst_port;
    char *interface;
};


void *recvTCP();
int sendTcp(struct message msg, uint8_t tcp_flag);

int openRawSocket(char *interface);
uint8_t *getMacFromInterface(char *interface, int socketDescriptor);
struct sockaddr_ll getInterfaceDevice(char *interface);
struct ip6_hdr getIPV6Header(char * src_ip, char * dst_ip);
struct tcphdr getTCPHeader(struct ip6_hdr iphdr, uint16_t dst_port, uint8_t tcp_flag);
uint8_t *getEthernetFrame(char *src_mac, char *dst_mac, struct ip6_hdr iphdr, struct tcphdr tcphdr);
void sendEthernetFrame(uint8_t *ether_frame, int socketDescriptor, struct sockaddr_ll device);

uint16_t checksum(uint16_t *, int);
uint16_t tcp6_checksum(struct ip6_hdr, struct tcphdr);
