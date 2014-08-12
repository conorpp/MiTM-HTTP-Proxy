#include "raw.h"
#include "tun.h"
#include "packetStructures.h"

int SelectFd(int fd){
    struct timeval time = {0, 100*1000};
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(fd, &fdset); 

    int ret = select(fd+1, &fdset,
                    NULL, NULL, &time);
    if (ret<0){
        perror("select");
        exit(2);
    }

    return (FD_ISSET(fd, &fdset));
}

int sread(int sockfd, void* buffer, int bufSize){
    int nread = read(sockfd, buffer, bufSize);
    if(nread < 0) {
        perror("read");
        close(sockfd);
        exit(1);
    }
    return nread;
}
void printProto(int p){
    switch((p)){
        case IP_ICMP:
            printf("icmp");
            break;
        case IP_UDP:
            printf("udp");
            break;
        case IP_TCP:
            printf("tcp");
            break;
        default:
            printf("unknown");
            break;
    }
}
int main(int argc, char* argv[]){
    if (getuid() != 0){
        printf("You need root permission to use raw sockets\n");
        return 1;
    }
    IPSocket* raw;// = getRawSocket("127.0.0.2",44,0x44, RAW_BIND);
    IPSocketList* socks = getIPSocketList();
    IPSocketNode* p;
    char tun_name[1000] = "tun0";
    int tunfd = tun_alloc(tun_name, IFF_TUN|IFF_NO_PI);
    // addIPSocket(socks, raw);
    char buf[10000];
    ip_h* ipHeader;
    while (1) {
        SelectIPSocket(socks);
        
        // TODO ifconfig up tun0 and ping it to confirm protocol are printing
        if (SelectFd(tunfd)){
            int nread = sread(tunfd,buf,sizeof(buf));
            if (nread >= IP4_H_SIZE){
                ipHeader = (ip_h*)buf;
                printProto(ipHeader->protocol);
                printf("\n");
                //if (ipHeader->protoc)
                raw = addUniqueIPSocket(socks, 
                ipHeader->dstIp, 44, ipHeader->protocol, 0);

                Sendto(raw, buf+IP4_H_SIZE, nread-IP4_H_SIZE);
            }
            
       }
        
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
            printf("recv %d bytes from %d: %s\n", nread,p->i, buf+20);
            //break;
        }
        //break;
   }

    freeIPSocketList(&socks);
    return 0;
}
