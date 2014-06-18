#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

#include <sys/socket.h>
#include <sys/types.h> 
#include <sys/wait.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>

#include <arpa/inet.h>

/*Error Checking
 * */

// die if two values equal each other.
// specify a message to die with.
void p_assert_false(int *ptr, int *val, char *msg);

// exit with a message along with errno message if 
// it's set
void die(const char *msg);

// Handler to reap zombie processes
void sigchld_handler(int s){
    while(waitpid(-1, NULL, WNOHANG) > 0);
}
/* * */


void p_assert_false(int *ptr, int *val, char *msg){
    if (*ptr == *val)
        die(msg);
}

void die(const char *msg){
    if (!errno) printf("%s\n", msg);
    else perror(msg);
    fflush(stderr);
    fflush(stdout);
    exit(2);
}

/* Networking
 * */

// looks up a host and fills addrinfo res 
// with tcp addr/port/protocol/family options
// Be sure to free res when finished.
struct addrinfo* getTCPInfo(char *hostname, char* port);

// Binds to an address and port
// to liston on for TCP connections
// Binds to localhost if addr is NULL
int Listen(void *addr, char *port);

// Establishes a TCP connection with 
// a host on a particular port and 
// returns the file descriptor
int Connect(char *hostname, int port);
/* * */

struct addrinfo* getTCPInfo(char *hostname, char* port){
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int ec = getaddrinfo(hostname, port, &hints, &res);
    //int ec = getaddrinfo("a.thumbs.redditmedia.com", "80", &hints, &res);
    if (ec != 0) {
        printf("getTCPInfo: %s\n",gai_strerror(ec));
        exit(3);
    }
    return res;
}

int Listen(void *addr, char *port){
    struct addrinfo hints, *res, *p;
    int sockfd, ec;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (addr == NULL) hints.ai_flags = AI_PASSIVE;  // take local ip addr
    
    ec = getaddrinfo(addr, port, &hints, &res);
    if (ec != 0) die(gai_strerror(ec));
    int yes =1;
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
    if (ec == -1){perror("bind");}
    return sockfd;
}

int Connect(char *hostname, int _port){
    int sockfd;
    if (_port>65535 || _port <1){
        printf("invalid port number: %d", _port);
        exit(2);
    }
    char port[60];
    sprintf(port, "%d", _port);
    struct addrinfo *p, *res;
    res = getTCPInfo(hostname, port);
    for (p = res; p != (struct addrinfo*)0; p=p->ai_next){
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol))<0){
            close(sockfd);
            perror("connect\n");
            continue;
        }
        break;
    }
    if (p == (struct addrinfo*) 0)
        die("could not find a sockfd for connect");
    freeaddrinfo(res);
    if ( connect(sockfd, p->ai_addr, p->ai_addrlen) < 0 )
        die("connect");
    return sockfd;
}


/* URL/text parsing
 * */

// Parses a full URL and fills in the host, port, and path

struct HTTPRequest{
    char* method, *url, *protocol;
    char* host, *path;
    int port,ssl;
};

#define HTTP_BUF_SIZE 10000
static char HTTP_BUF[HTTP_BUF_SIZE];

void parseURL(const char* url, char** host, char** path,int* port, int *ssl);

void parseHTTPRequest(const char* str, struct HTTPRequest* req){
    if (sizeof str > HTTP_BUF_SIZE){
        printf("HTTP request str is longer than %d bytes", HTTP_BUF_SIZE);
        exit(3);
    }
    int size, offset;
    
    // method
    if (sscanf(str, "%s", HTTP_BUF) != 1)
        die("invalid request string for method");
    req->method = (char *)malloc( (size = offset = strlen(HTTP_BUF)+1) );
    memmove(req->method, HTTP_BUF, size);
    // url
    
    if (sscanf(&str[offset], "%s", HTTP_BUF) != 1)
        die("invalid request string for url");
    req->url = (char *) malloc( (size = strlen(HTTP_BUF)+1) );
    memmove(req->url, HTTP_BUF, size);
    offset += (size);
    //printf("parsed url: %s\n", req->url);
    
    // protocol
    if (sscanf(&str[offset], "%s", HTTP_BUF) != 1)
        die("invalid request string for protocol");
    req->protocol = (char *) malloc( (size = strlen(HTTP_BUF)+1) );
    memmove(req->protocol, HTTP_BUF, size);
    parseURL(req->url, &req->host, &req->path, &req->port, &req->ssl);
    if (strncasecmp(req->method, "CONNECT", 7) == 0) req->ssl = 1;
}

void parseURL(const char* url, char** _host, char** _path, int* port, int* ssl){

    int offset = 0;
    int size;
    char *host = *_host, *path = *_path;

    if (strncasecmp(url, "http://", (offset=7)) == 0)
        *ssl = 0;
    else if (strncasecmp(url, "https://", (offset=8)) == 0)
        *ssl = 1;
    else 
        offset = 0;
    if (sscanf(&url[offset], "%[^/:]", HTTP_BUF) != 1)
        die("invalid url");

    offset += (size = strlen(HTTP_BUF)+1);
    *_host = (char*) malloc(size);
    memmove(*_host, HTTP_BUF, size);

    if (sscanf(&url[offset-1], ":%d%s", port, HTTP_BUF) != 2){
        if (sscanf(&url[offset-1], ":%d", port) != 1){
            if (sscanf(&url[offset-1], "%s", HTTP_BUF) != 1)
                sprintf(HTTP_BUF, "/");
            *port = 80;
        }
    }
    if (*port == 443) *ssl = 1;
    size = strlen(HTTP_BUF)+1;
    *_path = (char*) malloc(size);
    memmove(*_path, HTTP_BUF, size);
    
}

void freeURL(char* host, char* path){
    if (host != (char*) 0)
        free(host);
    if (path != (char*) 0)
        free(path);
}

void freeHTTPRequest(struct HTTPRequest* req){

    if (req->method != (char*) 0)
        free(req->method);
    if (req->url != (char*) 0)
        free(req->url);
    if (req->protocol != (char*) 0)
        free(req->protocol);
    freeURL(req->host, req->path);
}













#endif
