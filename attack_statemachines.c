#include <stdint.h>
#include "message/message.h"

int tcpconnect_statemachine(int state, uint8_t flags)
{
  if (state == 0 && flags == SYN_FLAG)
    return 0;
  
  return -1;
}

int tcphalfopen_statemachine(int state, uint8_t flags)
{
  if (state == 0 && flags == SYN_FLAG)
    return 1;
  if (state == 1 && flags & RST_FLAG)
    return 0;

  return -1;
}

int tcpfin_statemachine(int state, uint8_t flags)
{
  if (state == 0 && flags == FIN_FLAG)
    return 0;
  return -1;
}

