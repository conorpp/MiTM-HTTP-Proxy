
#include "pcap.h"
#include "libnet/libnetcore.h"

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
pcap_t* handle;

void die(const char *m){
    printf("%s\n",m);
    exit(1);
}
struct addrinfo* getTCPInfo(char *hostname, char* port){
    struct addrinfo hints, *res;
    int ec;
    memset(&hints, 0, sizeof hints);
    // Use IPv4
    hints.ai_family = AF_INET;
    // Use TCP
    hints.ai_socktype = SOCK_STREAM;
    // Lookup host
    if ( (ec = getaddrinfo(hostname, port, &hints, &res)) != 0)
        die(gai_strerror(ec));
    return res;
}

int Listen(void *addr, char *port){
    struct addrinfo *res, *p;
    int sockfd;

    res = getTCPInfo(addr, port);
    int yes = 1;
    // loop through results until a suitable bind is made.
    for (p = res; p!=NULL; p = res->ai_next){
        if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
            perror("bad file descriptor");
            continue;
        }
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(yes), sizeof(int))==-1)
            die("setsockopt");

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1){
            perror("bind");
            close(sockfd);
            continue;
        }
        break;
    }
    if (p == NULL)
        die("server failed to bind");
    if (listen(sockfd, 12) == -1) {
        die("Could not listen");
    }
    freeaddrinfo(res); // all done with this structure
    return sockfd;
}

void looper(u_char* args, const struct pcap_pkthdr* header, const u_char* packet ){
    
    printf("got packet of len %d\n", header->len); 
    
    ether_h* eth = (ether_h*)(packet + 0);
    ip_h* ip = (ip_h*)(packet + ETHER_H_SIZE);
    tcp_h* tcp = (tcp_h*)(packet + ETHER_H_SIZE + IP4_H_SIZE);

    printf("dst port = %d\n", ntohs(tcp->dst_port));

    pcap_inject(handle, packet, header->len);
}

int main(int argc, char* argv[]){
    if (argc<3){
        printf("forgot device, filter\n");    
    }
    Listen(NULL, "5999");
    printf("sacrificing port 5999\n");
    handle = setPromiscuous(argv[1], argv[2]);
    pcap_loop(handle, 0, looper, NULL);

    return 0;    
}


