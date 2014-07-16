/* ARP functionality.
* */

#ifndef _ARP_H_
#define _ARP_H_

#include "tcp.h"
#include "libnet/libnetcore.h"
#include "pcapSettings.h"
#include "pcap.h"

char ERRBUF[LIBNET_ERRBUF_SIZE];
// Sends an arp packet of type ARPOP_REPLY or ARPOP_REQUEST
void sendArp(int type, uint32_t ipsrc, uint8_t* hwsrc, uint32_t ipdst, uint8_t* hwdst);


// arp poision a target with another ip address.  Need target's
// hw addr.
int arpPoison(char* ipTarget, char* ipGateway, uint8_t* targetHwAddr);



#endif
