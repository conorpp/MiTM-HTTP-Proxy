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

struct{
    struct addr hostHw;
    struct addr hostIp;
    
    struct addr defaultIp;
    struct addr defaultHw;

    char* device;
    pcap_t* pcap;
}Settings;


// Puts network device in capture mode.
// applies the given tcpdump filter
pcap_t* setPromiscuous(char* device, char* filter);

// Fills in the given hwbuf with the MAC address
// of the given host machine ip.
// hwbuf must have enough space for atleast 6 bytes
int getMacAddress(struct addr* ip, struct addr* hwbuf);

// Generate a ARP Packet
///@param packet pass in NULL to return a new packet
/// otherwise it will be filled in and returned.
#define ARP_REQUEST 1
#define ARP_REPLY 2
uint8_t* getArpPacket(
        void* packet,
        int operation,
        uint8_t* srcHw,
        uint32_t srcIp,
        uint8_t* dstHw,
        uint32_t dstIp);

 
// free a generate arp packet
void freeArpPacket(void* packet);

// Fill in a ether_h 
#define ETH_PROTO_ARP 0x0806
void fillEthPacket(ether_h* eth,
        uint8_t* dst_hw,
        uint8_t* src_hw,
        uint16_t proto);

// Fill in buf with the IP address of given interface/device
void getHostIp(struct addr* buf, char* device);

// Fill in buf with MAC address of given interface/device
void getHostHw(struct addr* buf, char* device);

// Get the MAC address of default gateway on machine
void getDefaultGatewayHw(struct addr* buf);

// Get the IP address of the default gateway on machine
void getDefaultGatewayIp(struct addr* ip);

#endif
