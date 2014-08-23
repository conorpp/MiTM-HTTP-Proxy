#include "pcap.h"
#include "packetStructures.h"
#include "utils.h"

pcap_t* setPromiscuous(char* device, char* filter){
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;      /* The compiled filter */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */


    /* Find the properties for the device */
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, errbuf);
        net = 0;
    }
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return (pcap_t*) 0;
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return (pcap_t*) 0;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return (pcap_t*) 0;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device);
        return (pcap_t*) 0;
    }
    return handle;
}

void getDefaultGatewayIp(struct addr* ip){
    route_t* router = route_open();

    struct route_entry entry;

    addr_pton("8.8.8.8", &entry.route_dst);

    route_get(router, &entry);

    memmove(ip, &entry.route_gw, sizeof(struct addr));
    printf("gw ip is %s\n", addr_ntoa(&entry.route_gw));
    route_close(router);

}
// subroutine for getDefaultGatewayHw
static int _findHwAddrLoop(const struct arp_entry* entry, void* arg){
    struct arp_entry* target = (struct arp_entry*)arg;
    if ( target->arp_pa.addr_ip == entry->arp_pa.addr_ip){
        memmove(&target->arp_ha, &entry->arp_ha,
                sizeof(struct addr));
    }
    return 0;
}
void getDefaultGatewayHw(struct addr* buf){
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

void getHostHw(struct addr* buf, char* device){
    eth_t* eth = eth_open(device);
    eth_addr_t ethAddr;

    eth_get(eth, &ethAddr);
    memmove(&buf->addr_eth, &ethAddr, 6);
    eth_close(eth);
}



void getHostIp(struct addr* buf, char* device){
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
void fillEthPacket(ether_h* eth,
        uint8_t* dst_hw,
        uint8_t* src_hw,
        uint16_t proto){
    memmove(eth->dst_hw, dst_hw, 6);    
    memmove(eth->src_hw, src_hw, 6);    
    eth->protocol = htons(proto);
};


#define ARP_REQUEST 1
#define ARP_REPLY 2
uint8_t* getArpPacket(
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

void freeArpPacket(void* packet){
    if (packet !=  0){
        free(packet);
    }
}

int getMacAddress(struct addr* ip, struct addr* hwbuf){
    struct pcap_pkthdr header;  
    memset(&header,0,sizeof(struct pcap_pkthdr));  
    const u_char *packet;       
    char filter_exp[60];
    static uint8_t hwBc[] = {0xff,0xff,0xff,0xff,0xff,0xff};

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



