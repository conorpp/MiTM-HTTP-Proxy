#include <sys/stat.h>
#include <sys/ioctl.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "libnet/libnetcore.h"

#include "pcap.h"
#include "packetStructures.h"
#define MAX(x,y) ((x) > (y) ? (x) : (y)) 
int tun_alloc(char *dev, int flags) {

    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    /* Arguments taken by the function:
     *
     * char *dev: the name of an interface (or '\0'). MUST have enough
     *   space to hold the interface name if '\0' is passed
     * int flags: interface flags (eg, IFF_TUN etc.)
     */

    /* open the clone device */
    if( (fd = open(clonedev, O_RDWR)) < 0 ) {
        return fd;
    }

    /* preparation of the struct ifr, of type "struct ifreq" */
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

    if (*dev) {
        /* if a device name was specified, put it in the structure; otherwise,
         * the kernel will try to allocate the "next" device of the
         * specified type */
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    /* try to create the device */
    if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
        close(fd);
        return err;
    }

    /* if the operation was successful, write back the name of the
     * interface to the variable "dev", so the caller can know
     * it. Note that the caller MUST reserve space in *dev (see calling
     * code below) */
    strcpy(dev, ifr.ifr_name);

    /* this is the special file descriptor that the caller will use to talk
     * with the virtual interface */
    return fd;
}
void hexDump(void* _buf, int l){
    uint8_t* buf = (uint8_t*)_buf;
    for (int i=0; i<l; i++){
        printf("%x:", buf[i]);
    }
    printf("\n");
}

#define SRC_IP_OFFSET 12 
#define DST_IP_OFFSET 16
uint32_t getNetworkIp(char* ip){
    struct in_addr ipvalue;
    int ec;
    ec = inet_pton(AF_INET, ip, &ipvalue);
    if (ec != 1){
        printf("Invalid ip address %s\n", ip);
        exit(2);
    }
    return ipvalue.s_addr;
}
void setSrcIp(void* buf, char* ip){
    int nip = getNetworkIp(ip);
    memmove(buf + SRC_IP_OFFSET, (uint8_t*)&nip, 4); 
}
void setDstIp(void* buf, char* ip){
    int nip = getNetworkIp(ip);
    memmove(buf + DST_IP_OFFSET, (uint8_t*)&nip, 4); 
}

void setSrcHw(void* buf, uint8_t* hw){
    memmove(buf+6, hw, 6);
}

void setDstHw(void* buf, uint8_t* hw){
    memmove(buf+0, hw, 6);
}

int sread(int sockfd, void* buffer, int bufSize){
    int nread = read(sockfd, buffer, bufSize);
    if(nread < 0) {
        perror("Reading from interface");
        close(sockfd);
        exit(1);
    }
    return nread;
}

int swrite(int sockfd, void* buffer, int bufSize){
    int nwrite = write(sockfd, buffer, bufSize);
    if(nwrite < 0) {
        perror("Reading from interface");
        close(sockfd);
        exit(1);
    }
    return nwrite;
}

int sendToKernal(int sockfd, void* buf, int bufLength){
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons (0);   /* you byte-order >1byte header values to network
                                   byte order (not needed on big endian machines) */
    sin.sin_addr.s_addr = inet_addr ("127.0.0.1");

    return sendto(sockfd, buf, bufLength,
            0,(struct sockaddr *) &sin, sizeof(struct sockaddr));

}

uint8_t hwTap1[] = {0xca, 0xfe, 0xba, 0xaa, 0xbe, 0x00};
uint8_t hwTap2[] = {0xca, 0xfe, 0xba, 0xaa, 0xbe, 0x01};
uint8_t hwLoc[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

int main(int argc , char* argv[]){
    
    if (argc < 5){
        printf("usage:\n");
        printf("    ./%s <tunsrc> <tunsrc ip>"
                "<tundst> <tundst ip>\n", argv[0]);
        exit(1);
    }
    char tun_name[IFNAMSIZ];
    int nread;
    /* Connect to the device */
    strcpy(tun_name, argv[1]);
    int tun_src_fd = tun_alloc(tun_name, IFF_TUN|IFF_NO_PI);

    strcpy(tun_name, argv[3]);
    int tun_dst_fd = tun_alloc(tun_name, IFF_TUN|IFF_NO_PI);
    
    char* src_tun_ip = argv[2];
    char* dst_tun_ip = argv[4];

    printf("binded to src %s - %s\n", argv[1], src_tun_ip);
    printf("binded to dst %s - %s\n", argv[3], dst_tun_ip);

    if(tun_src_fd < 0 || tun_dst_fd < 0){
        perror("Allocating interface");
        exit(1);
    }
    char buffer[1500];

    int ethLayerSize = 0;//ETHER_H_SIZE;
    int ipLayerSize = ethLayerSize + IP4_H_SIZE;

    int maxfd = MAX(tun_src_fd, tun_dst_fd);
    
    int rawfd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (rawfd < 0){
        perror("raw socket");
        exit(2);
    }
    int one = 1;
    const int* val = &one;
    if(setsockopt(rawfd, 
        IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
        perror("setsockopt()");
        exit(2);
    }
    while(1) {
#if 1
        fd_set fdset;

        FD_ZERO(&fdset);
        FD_SET(tun_src_fd, &fdset); 
        FD_SET(tun_dst_fd, &fdset);
        int ret = select(maxfd+1, &fdset, NULL, NULL, NULL);
        
        if (ret<0){
            perror("select");
            exit(2);
        }

        if (FD_ISSET(tun_src_fd, &fdset)){
            nread = sread(tun_src_fd,buffer,sizeof(buffer));
            printf("src tun read %d bytes from ", nread);
            if (nread >= ipLayerSize){
                printf("ip packet\n");
                //setDstHw(buffer, hwLoc);
                //setSrcHw(buffer, hwTap2);
                //setSrcIp(buffer+ethLayerSize, "127.0.0.1");
                hexDump(buffer, nread);
                printf("dst ip switched\n");
                setDstIp(buffer+ethLayerSize, "127.0.0.1");
                hexDump(buffer, nread);
                //swrite(tun_dst_fd, buffer, nread);
                sendToKernal(rawfd, buffer, nread);
            }else{
                printf("unknown packet\n");
            }
        }

        if (FD_ISSET(tun_dst_fd, &fdset)){
            nread = sread(tun_dst_fd,buffer,sizeof(buffer));
            printf("dst tun read %d bytes from ", nread);
            if (nread >= ipLayerSize){
                printf("ip packet\n");
                //setDstHw(buffer, hwLoc);
                //setSrcHw(buffer, hwTap1);
                //setSrcIp(buffer+ethLayerSize, "55.55.55.55");
                //setDstIp(buffer+ethLayerSize, "127.0.0.1");
                //swrite(tun_src_fd, buffer, nread);
                swrite(tun_src_fd, buffer, nread);
            }else{
                printf("unknown packet\n");
            }
        }
        continue;
        // DONE;
#endif
        nread = sread(tun_src_fd,buffer,sizeof(buffer));
        hexDump(buffer, nread);

        printf("Read %d bytes from device %s\n", nread, tun_name);

        if (nread >= ethLayerSize){
            ether_h *eth = (ether_h*) (buffer);
            if (nread >= ipLayerSize){
                ip_h* ip = (ip_h*)(buffer+ethLayerSize);
                struct in_addr addr;
                addr.s_addr = ip->srcIp;
                printf("src ip: %s\n", inet_ntoa(addr));
                switch((ip->protocol)){
                    case 1:     // icmp
                        printf("icmp");
                    break;
                    case 6:     // tcp
                        printf("tcp");
                    break;
                    default:
                    printf("unknown (%x)", ip->protocol);

                    break;

                }
                setSrcIp(buffer+ethLayerSize, dst_tun_ip);
                setDstIp(buffer+ethLayerSize, "127.0.0.1");
                sendToKernal(rawfd, buffer, nread);
                // swap ip's here
            } 
        }
        printf("\n");
    
    }
    return 0;
}
