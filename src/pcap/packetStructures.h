/* Structure definitions for packet headers
* that can be used for typecasting
* */


#ifndef _PACKET_STRUCTURES_H_
#define _PACKET_STRUCTURES_H_

#include "libnet/libnetcore.h"

/* Ethernet header */
#define ETHER_H_SIZE 14
struct ethernet_h {
    u_char ether_dhost[6]; /* Destination host address */
    u_char ether_shost[6]; /* Source host address */
    uint16_t type; /* IP? ARP? RARP? etc */
};

#define ARP_H_SIZE 28
struct arp_h{
    uint16_t hw_t;      // 0 : 2
    uint16_t proto_t;   // 2 : 2
    uint8_t hwaddrlen;  // 4 : 1
    uint8_t protoaddrlen; // 5 : 1
    uint16_t op;            // 6 : 2
    uint8_t hwsrcaddr[6];  // 8 : 6
    uint32_t netsrc;       // 14 : 4
    uint8_t hwdstaddr[6];  // 18 : 6
    uint32_t netdst;       // 24 : 4
};


#endif
