
#include "tcp.h"

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
        perror("listen");
        exit(1);
    }
    freeaddrinfo(res); // all done with this structure
    return sockfd;
}

int Connect(char *hostname, int _port){
    int sockfd;
    if (_port>65535 || _port <1){
        printf("invalid port number: %d", _port);
        exit(2);
    }
    char port[6];
    sprintf(port, "%d", _port);
    struct addrinfo *p, *res;
    res = getTCPInfo(hostname, port);
    // Loop through until a proper socket is found
    for (p = res; p != (struct addrinfo*)0; p=p->ai_next){
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol))<0){
            close(sockfd);
            perror("connect\n");
            continue;
        }
        break;
    }
    if (p == (struct addrinfo*) 0)
        die("Connect: could not find a sockfd");
    freeaddrinfo(res);
    // establish connection
    if ( connect(sockfd, p->ai_addr, p->ai_addrlen) < 0 )
        die("connect");
    return sockfd;
}


