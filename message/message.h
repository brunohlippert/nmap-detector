#include <net/ethernet.h>
#include <netinet/in.h>	

// Define some constants.
#define ETH_HDRLEN 14 // Ethernet header length
#define IP6_HDRLEN 40 // IPv6 header length
#define TCP_HDRLEN 20 // TCP header length, excludes options data

// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header)
#define FRAME_LENGTH  6 + 6 + 2 + IP6_HDRLEN + TCP_HDRLEN

struct message
{
    char dst_addr[INET6_ADDRSTRLEN]; // 39 eh o tamanho maximo de um IPV6 contando os ":"
    char *interface;
};

int sendTcp(struct message msg);

int openRawSocket(char *interface);
uint8_t *getMacFromInterface(char *interface, int socketDescriptor);
struct sockaddr_ll getInterfaceDevice(char *interface);
struct ip6_hdr getIPV6Header(char * src_ip, char * dst_ip);
struct tcphdr getTCPHeader(struct ip6_hdr iphdr);
uint8_t *getEthernetFrame(char *src_mac, char *dst_mac, struct ip6_hdr iphdr, struct tcphdr tcphdr);
void sendEthernetFrame(uint8_t *ether_frame, int socketDescriptor, struct sockaddr_ll device);

uint16_t checksum(uint16_t *, int);
uint16_t tcp6_checksum(struct ip6_hdr, struct tcphdr);
