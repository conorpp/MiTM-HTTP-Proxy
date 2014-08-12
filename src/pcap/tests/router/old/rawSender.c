#include "raw.h"

int main(int argc, char* argv[]){
    if (getuid() != 0){
        printf("You need root to use raw sockets\n");
        return 1;
    }
    IPSocket* ipsock = getRawSocket("127.0.0.2", 0, 0x44, 0);
    
    while (1) {
        char* data = "hello";
        Sendto(ipsock, data, 6);
        
        sleep(1);
    }

    return 0;
}
