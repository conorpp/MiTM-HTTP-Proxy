#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "pcap.h"

#define ETH_PROTO_ARP 0x0806
static void fillEthPacket(ether_h* eth,
                uint8_t* dst_hw,
                uint8_t* src_hw,
                uint16_t proto){
    memmove(eth->dst_hw, dst_hw, 6);    
    memmove(eth->src_hw, src_hw, 6);    
    eth->protocol = htons(proto);
};


#define ARP_REQUEST 1
#define ARP_REPLY 2
static uint8_t* getArpPacket(
   int operation,
   uint8_t* srcHw,
   uint32_t srcIp,
   uint8_t* dstHw,
   uint32_t dstIp
){
    static uint8_t bc[] = {0xff,0xff,0xff,0xff,0xff,0xff};
    void* packet = malloc(sizeof(arp_h) + sizeof(ether_h));
    ether_h* eth = (ether_h*)(packet);

    fillEthPacket(eth, bc, srcHw, ETH_PROTO_ARP);


    arp_h* arp = (arp_h*)(packet + ETHER_H_SIZE);
    // 1 for ethernet
    arp->hw_type = htons(0x1);

    // 0x0800 for IPv4
    arp->protocol = htons(0x0800);

    arp->hwlen = 6;
    arp->protolen = 4;

    arp->op = htons(operation);

    memmove(arp->src_hw, srcHw, 6);
    memmove(arp->src_hw + 6, (uint8_t*)(&srcIp), 4);
    arp->src_ip = (srcIp);

    //memmove(arp->dst_hw, dstHw, 6);
    //arp->dst_ip = (dstIp);
    
    return (uint8_t*)packet;
}

static void freeArpPacket(arp_h* packet){
    if (packet != (arp_h*) 0){
        free(packet);
    }
}
static uint32_t IP(char* ip){
    struct in_addr addr;
    inet_aton(ip, &addr);
    return addr.s_addr;
}
uint8_t hwTap1[] = {0xca, 0xfe, 0xba, 0xaa, 0xbe, 0x00};
uint8_t hwTap2[] = {0xca, 0xfe, 0xba, 0xaa, 0xbe, 0x01};
uint8_t hwLoc[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
uint8_t hwWlan[] = {0x54, 0x27, 0x1e, 0xef, 0x04, 0x11};
uint8_t hwEth[] = {0x10, 0xc3, 0x7b, 0x4d, 0xc2, 0xbc};
// 10:c3:7b:4d:c2:bc
uint8_t hwRouter[] = {0xe0, 0x3f, 0x49, 0x9c, 0x67, 0x58};
uint8_t hwLaptop[] = {0x60, 0x67, 0x20, 0x2b, 0x34, 0x94};

int main(int argc, char* argv[]){

    uint8_t* arp = getArpPacket(ARP_REPLY,
                                hwEth,
                                IP("192.168.1.3"),
                                hwRouter,
                                IP("192.168.1.1")
                                );

    printf("got packet\n");
    pcap_t* cap = setPromiscuous("eth0","arp");

    printf("got interface\n");
    pcap_inject(cap, arp, ETHER_H_SIZE + ARP_H_SIZE);

    printf("sent arp\n");
    
    return 0;    
}



