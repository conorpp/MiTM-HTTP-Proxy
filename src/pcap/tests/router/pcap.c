#include "pcap.h"
#include "packetStructures.h"


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

static unsigned int getIpInt(char* ip){
    struct in_addr addr;
    inet_aton(ip, &addr);
    return addr.s_addr;
}
int getMacAddress(char* ip, uint8_t* hwbuf, pcap_t* handle){
    static uint8_t hwb[] = {0xff,0xff,0xff,0xff,0xff,0xff};
    struct pcap_pkthdr header;  /* The header that pcap gives us */
    memset(&header,0,sizeof(struct pcap_pkthdr));  /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */
    char filter_exp[60];

    
    sprintf(filter_exp, "arp[14:4] == %u", ntohl(getIpInt(ip)));
    printf("%s\n", filter_exp);

    //sendArp(ARPOP_REQUEST, Settings.hostIp, Settings.hostHwAddr, getIpInt(ip), hwb);
    //while(!header.len)
    //    packet = pcap_next(handle, &header);

    if (header.len < (ARP_H_SIZE+ETHER_H_SIZE)){
        printf("received invalid packet of length %d/%d.\n", header.len, ARP_H_SIZE+ETHER_H_SIZE);
        return 1;
    }
    arp_h* arpReply = (arp_h*)(packet + ETHER_H_SIZE);
    printf("recieved MAC: \n");
    for(int i=0; i<6; i++){
        printf("%x", (hwbuf[i]=arpReply->src_hw[i]));
    }
    printf("\n");
    /* And close the session */
    pcap_close(handle);
    return 0;
}


