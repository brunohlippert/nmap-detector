#include <netinet/ip6.h> // struct ip6_hdr

#define PORTS_RANGE 65536

typedef struct
{
  char ip6[INET6_ADDRSTRLEN];
  int count;
  uint16_t ports[PORTS_RANGE];

  int tcpconnect_state;
  int tcphalf_state;
  int fin_state;
  int fpu_state;

  int tcpconnect_half_warn;
  int tcpconnect_warn;
  int tcphalf_warn;
  int fin_warn;
  int fpu_warn;
} Host_entry;