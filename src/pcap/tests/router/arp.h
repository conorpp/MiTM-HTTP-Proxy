/* ARP functionality.
* */

#ifndef _ARP_H_
#define _ARP_H_

#include <stdint.h>

char ERRBUF[1 << 10];
// Sends an arp packet of type ARPOP_REPLY or ARPOP_REQUEST
void sendArp(int type, uint32_t ipsrc, uint8_t* hwsrc, uint32_t ipdst, uint8_t* hwdst);


// arp poision a target with another ip address.  Need target's
// hw addr.
int arpPoison(char* ipTarget, char* ipGateway, uint8_t* targetHwAddr);


void sendEth(const uint8_t *dst, const uint8_t* src, uint16_t type,
                const uint8_t *payload, uint32_t payload_s );
 
#endif
