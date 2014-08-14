/* Structure definitions for packet headers
* that can be used for typecasting
* */


#ifndef _PACKET_STRUCTURES_H_
#define _PACKET_STRUCTURES_H_


/* Ethernet header */
#define ETHER_H_SIZE 14
typedef struct {
    u_char dst_hw[6]; /* Destination host address */
    u_char src_hw[6]; /* Source host address */
    uint16_t protocol; /* IP? ARP? RARP? etc */
} ether_h;

#define ARP_H_SIZE 28
typedef struct{
    uint16_t hw_type;      // 0 : 2
    uint16_t protocol;   // 2 : 2
    uint8_t hwlen;  // 4 : 1
    uint8_t protolen; // 5 : 1
    uint16_t op;            // 6 : 2
    uint8_t src_hw[6];  // 8 : 6
    uint32_t src_ip;       // 14 : 4
    uint8_t dst_hw[6];  // 18 : 6
    uint32_t dst_ip;       // 24 : 4
} arp_h;

#define IP4_H_SIZE 20
typedef struct{
    uint8_t version_hl; // 0
    uint8_t dscp_en;    // 1
    uint16_t length;    // 2
    uint16_t id;        // 4
    uint16_t flags_offset;  // 6
    uint8_t ttl;            // 8
    uint8_t protocol;       // 9
    uint16_t chksum;        // 10
    uint32_t srcIp;         // 12
    uint32_t dstIp;         // 16
    // optional header
} ip_h;

#define IP_ICMP 1
#define IP_UDP 17
#define IP_TCP 6

typedef struct{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t off;
    uint16_t win_size;
    uint16_t chksum;
    // urg pointer if urg is set
} tcp_h;


#endif


