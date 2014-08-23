/* Wrapper functions for packet capture functionality
* */

#ifndef _PCAP_H_
#define _PCAP_H_

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <dnet.h>
#include "pcap/pcap.h"
#include "arp.h"
#include "packetStructures.h"

// Puts network device in capture mode.
// applies the given tcpdump filter
pcap_t* setPromiscuous(char* device, char* filter);

// Fills in the given hwbuf with the MAC address
// of the given host machine ip.
// hwbuf must have enough space for atleast 6 bytes
int getMacAddress(struct addr* ip, struct addr* hwbuf);

struct{
    struct addr hostHw;
    struct addr hostIp;

    char* device;
    pcap_t* pcap;

}Settings;

#endif
