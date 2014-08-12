#include "raw.h"

int main(int argc, char* argv[]){
    if (getuid() != 0){
        printf("You need root permission to use raw sockets\n");
        return 1;
    }
    IPSocket* raw = getRawSocket("127.0.0.2",44,0x44, RAW_BIND);
    IPSocketList* socks = getIPSocketList();
    IPSocketNode* p;
    addIPSocket(socks, raw);
    char buf[1000];
    while (1) {
        printf("selecting\n");
        SelectIPSocket(socks);
        
        for(p=socks->list; p != NULL; p=p->next){
            if (!p->data_ready){
                printf("%d has nothing\n", p->i);
                if(p->data_misses > 12){
                    printf("removing %d\n",p->i);
                    removeIPSocket(socks, &p);
                    if (p == NULL)break;
                }
                continue;
            }
            int nread = Recvfrom(p->ipsock, buf, 1000);
            printf("recv %d: %s\n", p->i, buf+20);
            //break;
        }
        //break;
   }

    freeIPSocketList(&socks);
    return 0;
}
