#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <dnet.h>

int main(int argc, char* argv[]){
    if (argc < 2){
        printf("usage: ./%s <ip-addr>\n", argv[0]);    
        return 1;
    }
    printf("dnet is alive\n");

    arp_t* arper = arp_open();

    struct addr dst;
    struct addr hw;
    
    addr_pton(argv[1], &dst);
    struct arp_entry entry;
    
    memmove(&entry.arp_pa, &dst, sizeof(struct addr));

    int ec = arp_get(arper, &entry);

    if (ec != 0){
        printf("arp_get failed\n");
    }

    printf("got hw addr\n");

    unsigned char* hwaddr = (unsigned char*)&entry.arp_ha.addr_eth;

    for (int i=0; i<6 ; i++){
        printf("%x:", hwaddr[i]);
    }
    printf("\n");

    arp_close(arper);

    eth_t* eth = eth_open("eth0");
    printf("opened\n");
    eth_addr_t ethAddr;

    eth_get(eth, &ethAddr);
    printf("got\n");
    unsigned char* urMac = (unsigned char*) &ethAddr;
    printf("Your mac addr: ");
    for (int i=0; i<6 ; i++){
        printf("%x:", urMac[i]);
    }
    printf("\n");


    return 0;
}


