#include <netinet/ip6.h> // struct ip6_hdr

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
