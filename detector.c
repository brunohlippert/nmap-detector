#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>      // struct ifreq
#include <netinet/ip6.h> // struct ip6_hdr
#include <netinet/tcp.h> // struct tcphdr
#include <arpa/inet.h>   // inet_pton() and inet_ntop()
#include "message/message.h"
#include "pthread.h"

#define PORTS_RANGE 65536

typedef struct
{
  char ip6[INET6_ADDRSTRLEN];
  int count;
  uint16_t ports[PORTS_RANGE];

  int syn;
  int ack;
  int fin;
  int fpu;
} Host_entry;

int entriesIndex;
int size;
Host_entry *entries;

void *enforcer(void *input)
{
  while (1)
  {
    printf("==============================================================================\n");
    printf("\e[1;1H\e[2J");

    for (int i = 0; i < entriesIndex; i++)
    {
      Host_entry ent = entries[i];
      int portscount = 0;

      for (int j = 0; j < PORTS_RANGE; j++)
      {
        if (ent.ports[j] > 0)
        {
          // printf("source: %s, port %d\n ", ipv6src_str, j);
          portscount++;
        }
      }

      char ipv6src_str[INET6_ADDRSTRLEN + 1];
      ipv6src_str[INET6_ADDRSTRLEN] = '\0';
      memcpy(ipv6src_str, ent.ip6, INET6_ADDRSTRLEN);

      // port checking
      if (portscount > 1)
      {
        printf("Potential port scanning detected:\n\tSource: %s\n\tPort count: %d\n", ipv6src_str, portscount);

        if (ent.syn && ent.ack)
          printf("\tPotential 'TCP Connect' attack detected: %d ACK packets received\n", ent.ack);

        if (ent.syn && !ent.ack)
          printf("\tPotential 'TCP half-opening' attack detected: %d SYN packets received\n", ent.syn);

        if (ent.fin)
          printf("\tPotential 'FIN' attack detected: %d FIN packets received\n", ent.fin);

        if (ent.fpu)
          printf("\tPotential 'FIN PSH URG' attack detected: %d FPU packets received\n", ent.fpu);

        printf("\n");
      }
    }
    sleep(1);
  }
  return 0;
}

void process_packet(Host_entry *entry, uint8_t flags)
{
  if (flags == SYN_FLAG)
    entry->syn++;

  if (flags == ACK_FLAG)
    entry->ack++;

  if (flags == FIN_FLAG)
    entry->fin++;

  if (flags == FIN_PUSH_URG_FLAG)
    entry->fpu++;
}

void handle_packet(char ipv6_src[46], struct tcphdr *tcphdr)
{
  if (entriesIndex > size)
  {
    printf("HOST OVERFLOW!\n");
    return;
  }

  for (int i = 0; i < entriesIndex; i++)
  {
    if (!memcmp(ipv6_src, entries[i].ip6, INET6_ADDRSTRLEN))
    {
      // char ipv6src_str[INET6_ADDRSTRLEN + 1];
      // memset(ipv6src_str, '\0', INET6_ADDRSTRLEN + 1);
      // memcpy(ipv6src_str, ipv6_src, INET6_ADDRSTRLEN);
      // printf("src:\t%s\n", ipv6_src);
      // printf("entry:\t%s\n", entries[i].ip6);
      // printf("memcmp fix:\t%d\n", memcmp(ipv6_src, entries[i].ip6, INET6_ADDRSTRLEN));
      // printf("memcmp len:\t%d\n", memcmp(ipv6_src, entries[i].ip6, strlen(ipv6_src)));

      entries[i].count++;
      entries[i].ports[htons(tcphdr->th_dport)]++;
      uint8_t flags = tcphdr->th_flags;
      process_packet(&entries[i], flags);
      return;
    }
  }

  Host_entry entry;
  memcpy(entry.ip6, ipv6_src, INET6_ADDRSTRLEN);
  entry.count = 1;
  memset(entry.ports, 0, PORTS_RANGE * sizeof(uint16_t));
  entry.ports[htons(tcphdr->th_dport)]++;

  uint8_t flags = tcphdr->th_flags;
  process_packet(&entry, flags);

  entry.syn = 0;
  entry.ack = 0;
  entry.fin = 0;
  entry.fpu = 0;

  entries[entriesIndex] = entry;
  entriesIndex++;
}

void *scanner(void *input)
{
  char *interface = (char *)(input);
  printf("interface\t%s\n", interface);

  char ipv6[INET6_ADDRSTRLEN + 1];
  memset(ipv6, '\0', INET6_ADDRSTRLEN + 1);
  memcpy(ipv6, getIPV6FromInterface(interface), INET6_ADDRSTRLEN);
  printf("IPv6\t\t%s\n", ipv6);

  int sockfd;
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    perror("socket");

  uint8_t *raw_buffer = malloc(65536);

  while (1)
  {
    memset(raw_buffer, 0, 65536);

    ssize_t buflen = recvfrom(sockfd, raw_buffer, 65536, 0, NULL, NULL);
    if (buflen < 0)
    {
      perror("Error on recvfrom, size of buffer < 0. Exiting.");
      return (void *)-1;
    }

    struct ether_header *eth_hdr = (struct ether_header *)(raw_buffer);
    if (eth_hdr->ether_type == ntohs(0x86dd))
    {
      // Pega o header IPV6 e verifica o IP src (resposta da requisicao)
      struct ip6_hdr *iphdr = (struct ip6_hdr *)(raw_buffer + sizeof(struct ether_header));

      char ipv6_src[INET6_ADDRSTRLEN];
      memset(ipv6_src, '\0', INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6, &(iphdr->ip6_src), ipv6_src, INET6_ADDRSTRLEN);

      char ipv6src_str[INET6_ADDRSTRLEN + 1];
      memset(ipv6src_str, '\0', INET6_ADDRSTRLEN + 1);
      memcpy(ipv6src_str, ipv6_src, INET6_ADDRSTRLEN);

      if (iphdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == 6 && memcmp(ipv6, ipv6src_str, strlen(ipv6)))
      {
        /** TCP header **/
        struct tcphdr *tcphdr = (struct tcphdr *)(raw_buffer + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        handle_packet(ipv6_src, tcphdr);
      }
    }
  }
}

int main(int argc, char **argv)
{
  entriesIndex = 0;
  size = 10000;
  entries = malloc(size * sizeof *entries);

  char interface[32];
  strcpy(interface, argv[1]);

  pthread_t th_scanner;
  pthread_create(&th_scanner, NULL, scanner, interface);

  pthread_t th_enforcer;
  pthread_create(&th_enforcer, NULL, enforcer, NULL);

  pthread_join(th_enforcer, NULL);
  pthread_join(th_scanner, NULL);
}