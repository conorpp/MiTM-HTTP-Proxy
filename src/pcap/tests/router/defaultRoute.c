#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <dnet.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>


int main(int argc, char* argv[]){
    if (getuid() != 0){
        printf("You need to be root\n");    
        return 1;
    }

    route_t* router = route_open();

    struct route_entry entry;
    
    addr_pton("8.8.8.8", &entry.route_dst);

    route_get(router, &entry);

    printf("gateway is %s\n", addr_ntoa(&entry.route_gw));

    route_close(router);
    return 0;
}
