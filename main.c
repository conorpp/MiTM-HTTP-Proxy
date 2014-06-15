/*
    Server
*/
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>

#include "utils.h"

int proxyHTTP(struct HTTPRequest* req, FILE* c_rfd, FILE* c_wfd, FILE* s_rfd, FILE* s_wfd);
int proxyHTTPS(struct HTTPRequest* req,FILE* c_rfd, FILE* c_wfd, FILE* s_rfd, FILE* s_wfd);

int main(int argc, char *argv[]){
    struct sockaddr_storage their_addr;
    socklen_t slen;
    int ec, sockfd, newfd;
    
    char *localport = "9999";
    sockfd = Listen(NULL, localport);
    
    char line[10000];
    memset(line,0,10000);
    
    printf("Proxy listening on %s\n", localport);
    
    while(1){
        
        slen = sizeof their_addr;
        newfd = accept(sockfd, (struct sockaddr *)&their_addr, &slen);
        printf("got new connection\n");
        
        if (newfd == -1){
            perror("accept"); //continue;
        }
        
        if (fork() == 0){       // child process 
            close(sockfd);
            

            FILE* c_wfd = fdopen(newfd, "w");
            FILE* c_rfd = fdopen(newfd, "r");
            if ( fgets(line, sizeof(line), c_rfd ) == (char*) 0 )
                die("could not get input from client");
            
            struct HTTPRequest req; 
            parseHTTPRequest(line, &req);
            
            int serverfd = Connect(req.host, req.port);
            FILE* s_wfd = fdopen(serverfd, "w");
            FILE* s_rfd = fdopen(serverfd, "r");
            
            if (req.ssl){
                printf("PROXYING HTTPS (%d)\n", req.port);
                proxyHTTPS(&req, c_rfd, c_wfd, s_rfd, s_wfd);
            }else{
                printf("PROXYING HTTP (%d)\n", req.port);
                proxyHTTP(&req, c_rfd, c_wfd, s_rfd, s_wfd);
            }
            close(newfd);
            close(serverfd);
            exit(0);
        }else{//   parent
            close(newfd);
        }
    }
    fflush(stdout);

    return 0;
}


int proxyHTTP(struct HTTPRequest* req, FILE* c_rfd, FILE* c_wfd, FILE* s_rfd, FILE* s_wfd){
    int cl = -1, byte;
    char line[10000];
    
    printf("%% REQUEST %%\n"); 

    fprintf(stdout,"%s %s %s\n", req->method,req->path,req->protocol);
    fprintf(s_wfd,"%s %s %s\n", req->method,req->path,req->protocol);

    while ((fgets(line, sizeof line, c_rfd)) != (char *)0){
        (void) fputs(line, s_wfd);
        printf("%s", line);
        if (strcmp(line, "\n") == 0 || strcmp(line, "\r\n") == 0)
            break;
        if (strncasecmp(line, "Content-Length:", 15) == 0)
            cl = atol(&line[15]);
    }

    fflush(s_wfd);
    for (; cl-- > 0; byte = getc(c_rfd)){
        if (byte == EOF)
            continue;
        printf("%c", byte);
        putc(byte,s_wfd);
    }
    fflush(stdout);
    fflush(s_wfd);

    printf("%% RESPONSE %%\n");
    while((fgets(line, sizeof line, s_rfd) != (char *)0)){
        (void) fputs(line, c_wfd);
        printf("    %s",line);
        if (strcmp(line, "\n") == 0 || strcmp(line, "\r\n") == 0)
            break;
        if (strncasecmp(line, "Content-Length:", 15) == 0)
            cl = atol(&line[15]);
    }
    fflush(c_wfd);

    while( cl-- > 0 ){
        if ((byte = getc(s_rfd)) == EOF)
            continue;
        //                putchar(byte);
        putc(byte, c_wfd);
    }
    fflush(c_wfd);
    fflush(stdout);
    
    freeHTTPRequest(req);

    return 0;
}


int proxyHTTPS(struct HTTPRequest* req, FILE* c_rfd, FILE* c_wfd, FILE* s_rfd, FILE* s_wfd){
    char line[10000];
    struct timeval timeout;
    fd_set fdset;
    int maxfd, r;

    sprintf(line,"HTTP/1.0 200 Connection established\r\n\r\n");
    (void) fputs(line, c_wfd);
    printf("%s",line);
    (void) fflush(c_wfd);

    int cR = fileno(c_rfd);
    int cW = fileno(c_wfd);
    int sR = fileno(s_rfd);
    int sW = fileno(s_wfd);

    memset(&timeout, 0, sizeof timeout);
    timeout.tv_sec = 300;

    maxfd = cR > sR ? cR+1 : sR+1;

    for(;;){
        FD_ZERO(&fdset);
        FD_SET(cR, &fdset);
        FD_SET(sR, &fdset);

        r = select(maxfd, &fdset, (fd_set*)0, (fd_set*)0, &timeout);
        if (r == 0)
            die("timeout occured");

        if(FD_ISSET(cR, &fdset)){
            r = read(cR, line, sizeof line);
            if (r <= 0) break;
            r = write(sW, line, r);
            printf("(from client) %s", line);
        }else if(FD_ISSET(sR, &fdset)){
            r = read(sR, line, sizeof line);
            if (r <= 0) break;
            r = write(cW, line, r);
            printf("(from server) %s", line);
        }
        if (r <= 0) break;
    }

    freeHTTPRequest(req);

    return 0;
}



