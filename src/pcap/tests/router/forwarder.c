#include <dnet.h>
#include "raw.h"
#include "pcap.h"
#include "utils.h"
#include "packetStructures.h"


int main(int argc, char* argv[]){
    if (getuid() != 0){
        die("You need root.\n");
    }
    if (argc < 3){
        die("usage: %s <device> <bind-addr>", argv[0]);
    }
    initHost(argv[1]);

    int r;
    char buf[10000];
    char filter[100];
    struct addr gwIp;
    struct addr gwHw;
    struct addr targetIp;
    struct addr targetHw;
    struct pcap_pkthdr header;  
    ether_h* ethPacket;
    ip_h* ipPacket;
    uchar* packet;
    
    getDefaultGatewayIp(&targetIp);
    getDefaultGatewayHw(&targetHw);
    
    printf("gw ip: %x\n",gwIp.addr_ip);

    addr_pton(argv[2], &targetIp);
    getMacAddress(&targetIp, &targetHw);
    IPSocket* rawGw = getRawSocket(gwIp.addr_ip, 0, IP_ICMP, 0);
    IPSocket* rawTarget = getRawSocket(targetIp.addr_ip, 0, IP_ICMP, RAW_ETHER);
    // setsockopt(rawGw->sockfd, SOL_SOCKET, SO_BINDTODEVICE, argv[1], strlen(argv[1]));
    // setsockopt(rawTarget->sockfd, SOL_SOCKET, SO_BINDTODEVICE, argv[1], strlen(argv[1]));
    uint8_t* H = (uint8_t*)&targetHw.addr_eth;
    sprintf(filter, 
            "(ether[6:4] == 0x%x%x%x%x && ether[10:2] == 0x%x%x)", 
            H[0], H[1], H[2], H[3], H[4], H[5] );
    pcap_t* cap = setPromiscuous(argv[1], filter);
    for(;;){
        memset(&header,0, sizeof(struct pcap_pkthdr)); 
        packet = (uchar*)pcap_next(cap, &header);
        if (header.len >= ETHER_H_SIZE){
            ethPacket = (ether_h*)packet;
            switch(ntohs(ethPacket->protocol)){
                case 0x0800:    // IPv4
                    if (header.len >= ETHER_H_SIZE + IP4_H_SIZE){
                        ipPacket = (ip_h*)(packet + ETHER_H_SIZE );
                        switch(ipPacket->protocol){
                            case IP_ICMP:
                                printf(" ICMP from %s %d bytes\n", inet_ntoa(rawTarget->addr.sin_addr),header.len);
                                
                                Sendto(rawGw, packet + IP4_H_SIZE + ETHER_H_SIZE, header.len - (ETHER_H_SIZE+IP4_H_SIZE));
                                r = Recvfrom(rawGw, buf, sizeof(buf));
                                printf("gateway returned %d ICMP bytes\n",r);
                                //r = Sendto(rawTarget, buf, r);
                                //printf("send %d ICMP bytes to target\n",r);
                            break;
                            default:
                            break;
                        }
                    }else{
                    }
                break;
                
            }
        }else{
        }
    }

}
