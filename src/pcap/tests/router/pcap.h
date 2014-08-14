/* Wrapper functions for packet capture functionality
* */

#ifndef _PCAP_H_
#define _PCAP_H_

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "pcap/pcap.h"
#include "arp.h"
#include "packetStructures.h"

// Puts network device in capture mode.
// applies the given tcpdump filter
pcap_t* setPromiscuous(char* device, char* filter);

// Fills in the given hwbuf with the MAC address
// of the given host machine ip.
// hwbuf must have enough space for atleast 6 bytes
int getMacAddress(char* ip, uint8_t* hwbuf, pcap_t*);


#endif
