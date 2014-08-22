
#include <dnet.h>
#include <stdio.h>
#include <string.h>

int getAddr(const struct arp_entry *entry, void *arg){

    struct arp_entry* target = (struct arp_entry*)arg;
    if ( target->arp_pa.addr_ip
            == entry->arp_pa.addr_ip){
        memmove(&target->arp_ha, &entry->arp_ha,
                            sizeof(struct addr));
    }
    return 0;
}

int main(int argc, char* argv[]){
    arp_t* arper = arp_open();
    if (argc < 2){
        printf("usage: ./%s <ip-addr>\n", argv[0]);    
        return 1;
    }

    struct arp_entry entry;

    memset(&entry,0,sizeof(struct arp_entry));
    addr_pton(argv[1], &entry.arp_pa);

    printf("IP requested: %s\n", addr_ntoa(&entry.arp_pa));
    int ec = arp_get(arper, &entry);

    if (ec != 0){
        arp_loop(arper, getAddr, &entry);
        if (entry.arp_ha.addr_type == 0){
            printf("finding address failed.\n");
        }
    }

    printf("got hw addr for %s\n",argv[1]);

    unsigned char* hwaddr = (unsigned char*)&entry.arp_ha.addr_eth;

    for (int i=0; i<6 ; i++){
        printf("%x:", hwaddr[i]);
    }
    printf("\n");

    arp_close(arper);
    return 0;
}


