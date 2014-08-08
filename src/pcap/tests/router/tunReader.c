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

void updateIPChecksum(void* buf){
    uint8_t* IP = (uint8_t*)buf;
    uint32_t sum = 0;
    uint32_t add;
    int i = 0;

    for (; i<10; i+=2)
        sum += ((IP[i] << 8) | IP[i+1]);

    for (i=12; i<20; i+=2)
        sum += ((IP[i] << 8) | IP[i+1]);

    while (sum & 0xffff0000){
        add = sum & 0xffff0000;
        sum &= 0xffff;
        sum += (add >> 16);
    }
    sum = ~sum & 0xffff;
    *(IP+10) = (sum & 0xff00) >> 8;
    *(IP+11) = (sum & 0xff);
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

int sendToKernal(int sockfd, char* ip, void* buf, int bufLength){
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons (0);   /* you byte-order >1byte header values to network
                                   byte order (not needed on big endian machines) */
    sin.sin_addr.s_addr = inet_addr (ip);

    return sendto(sockfd, buf, bufLength,
            0,(struct sockaddr *) &sin, sizeof(struct sockaddr));

}

uint8_t hwTap1[] = {0xca, 0xfe, 0xba, 0xaa, 0xbe, 0x00};
uint8_t hwTap2[] = {0xca, 0xfe, 0xba, 0xaa, 0xbe, 0x01};
uint8_t hwLoc[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
uint8_t hwWlan[] = {0x54, 0x27, 0x1e, 0xef, 0x04, 0x11};
uint8_t hwEth[] = {0x10, 0xc3, 0x7b, 0x4d, 0xc2, 0xbc};
// 10:c3:7b:4d:c2:bc
uint8_t hwRouter[] = {0xe0, 0x3f, 0x49, 0x9c, 0x67, 0x58};
uint8_t hwLaptop[] = {0x60, 0x67, 0x20, 0x2b, 0x34, 0x94};
//60:67:20:2b:34:94

void sendEth(uint8_t* src, uint8_t* dst, uint8_t* pl, uint8_t num, libnet_t* libnet){
    static libnet_ptag_t t = 0;
    // 0x800 is ipv4 code for ethernet
    t = libnet_build_ethernet(dst, src, 0x0800, pl, num, libnet,t);
    if (t == -1){
        fprintf(stderr, "Can't build ethernet header: %s\n",
                libnet_geterror(libnet));
        return;
    }

    int ec = libnet_write(libnet);
    if (ec == -1){
        fprintf(stderr, "Write error: %s\n", libnet_geterror(libnet));
    }
    else{
        fprintf(stdout, "Wrote %d byte Eth packet\n", ec);
    }


}

int main(int argc , char* argv[]){
    
    if (argc < 5){
        printf("usage:\n");
        printf("    ./%s <tunsrc> <tunsrc ip>"
                "<tundst> <tundst ip>\n", argv[0]);
        exit(1);
    }
    char tun_name[IFNAMSIZ];
    char ERRBUF[LIBNET_ERRBUF_SIZE];
    int nread;
    /* Connect to the device */
    strcpy(tun_name, argv[1]);
    int tun_src_fd = tun_alloc(tun_name, IFF_TUN|IFF_NO_PI);

    strcpy(tun_name, argv[3]);
    int tun_dst_fd = tun_alloc(tun_name, IFF_TUN|IFF_NO_PI);
    
    char* src_tun_ip = argv[2];
    char* dst_tun_ip = argv[4];
    
    libnet_t* libnet = libnet_init(LIBNET_LINK_ADV,
                                    "wlan1",
                                   ERRBUF );

    printf("binded to src %s - %s\n", argv[1], src_tun_ip);
    printf("binded to dst %s - %s\n", argv[3], dst_tun_ip);

    if(tun_src_fd < 0 || tun_dst_fd < 0){
        perror("Allocating interface");
        exit(1);
    }
    char buffer[1500];

    int ethLayerSize = 0;
    //int ethLayerSize = ETHER_H_SIZE;
    int ipLayerSize = ethLayerSize + IP4_H_SIZE;

    int maxfd = MAX(tun_src_fd, tun_dst_fd);
    
    int rawfd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    int rawipfd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
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
            printf("src tun read %d bytes from \n", nread);
            if (nread >= ipLayerSize){
                ip_h* ip = (ip_h*)(buffer+ethLayerSize);
                //if (ip->protocol != 1){
                //    printf("ignoring\n");
                //    goto next;
                //}
                //setDstHw(buffer, hwLoc);
                //setSrcHw(buffer, hwTap2);
                //setSrcIp(buffer+ethLayerSize, "192.168.1.3");
                setSrcIp(buffer+ethLayerSize, "192.168.1.3");
                setDstIp(buffer+ethLayerSize, "192.168.1.24");
                updateIPChecksum(buffer + ethLayerSize);
                sendEth(hwWlan, hwLaptop, (uint8_t*)buffer + ethLayerSize, nread, libnet);
                //swrite(tun_src_fd, buffer, nread);
                //sendToKernal(rawipfd, "192.168.1.24", buffer + ethLayerSize + ipLayerSize,
                //                                    nread - (ethLayerSize + ipLayerSize));
            }else{
                printf("unknown packet\n");
            }
        }
        if (FD_ISSET(tun_dst_fd, &fdset)){
            nread = sread(tun_dst_fd,buffer,sizeof(buffer));
            printf("DST tun read %d bytes\n", nread);
            if (nread >= ipLayerSize){
                //setDstHw(buffer, hwLoc);
                //setSrcHw(buffer, hwTap1);
                setSrcIp(buffer+ethLayerSize, "44.44.44.44");
                setDstIp(buffer+ethLayerSize, "192.168.1.24");
                updateIPChecksum(buffer + ethLayerSize);
                //swrite(tun_src_fd, buffer, nread);
                swrite(tun_dst_fd, buffer, nread);
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
                //sendToKernal(rawfd, buffer, nread);
                // swap ip's here
            } 
        }
        printf("\n");
    
    }
    return 0;
}
