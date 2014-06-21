/*
    Server
*/

#include "utils.h"
#include "tcp.h"
#include "http.h"
#include "ssl.h"
#include "reader.h"

struct SSLConnection {
    int socket;
    SSL *sslHandle;
    SSL_CTX *sslContext;
};


int proxyHTTP(HTTPRequest* req, int clientfd, int serverfd);
int proxyHTTPS(HTTPRequest* req, struct SSLConnection* ssl,int clientfd, int serverfd);


void proxyhttps(int clientfd, int serverfd);

int main(int argc, char *argv[]){
    struct sockaddr_storage their_addr;
    socklen_t slen;
    int sockfd, newfd;
    if (argc<4){
        die("you forgot port , cert , privkey\n");
    }
    char line[10000];
    memset(line,0,10000);
    
    signal(SIGCHLD, sigchld_handler);
    SSL_Init(argv[2], argv[3]);
    sockfd = Listen(NULL, argv[1]);
    
    printf("Proxy listening on %s\n", argv[1]);
    
    while(1){
        
        slen = sizeof their_addr;
        newfd = accept(sockfd, (struct sockaddr *)&their_addr, &slen);
        printf("got new connection\n");
        
        if (newfd == -1){
            perror("accept"); //continue;
        }
        
        if (fork() == 0){       // child process 
            close(sockfd);
            
            int r, o=0;
            while (  (r = read(newfd, &line[o], 1)) > 0){
                if (o>9999)
                    die("buffer space exceeded.");
                if (line[o] == '\n'){
                    line[o+1] = '\0';
                    break;
               }
                ++o;
            }
            if (!o)die("could not get input from client");
            printf("gotline: %s", line);
            HTTPRequest req; 
            parseHTTPRequest(line, &req);
            printf("connecting to %s %d", req.host, req.port);
            int serverfd = Connect(req.host, req.port);
            
            if (req.ssl){
                printf("PROXYING HTTPS (%d)\n", req.port);
                proxyhttps(newfd, serverfd);
                //proxyHTTPS(&req, &ssls, newfd, serverfd);
            }else{
                //FILE* s_wfd = fdopen(serverfd, "w");
                //FILE* c_wfd = fdopen(newfd, "w");
                //FILE* c_rfd = fdopen(newfd, "r");
                //FILE* s_rfd = fdopen(serverfd, "r");
                printf("PROXYING HTTP (%d)\n", req.port);
                proxyHTTP(&req, newfd, serverfd);
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


int proxyHTTP(HTTPRequest* req, int clientfd, int serverfd){
    int cl = -1, r;
    char line[10000];
    Reader* c_reader = openReader(read, clientfd, 9999, '\n', 8);
    Reader* s_reader = openReader(read, serverfd, 9999, '\n', 8);
    printf("%% REQUEST %%\n"); 

    fprintf(stdout,"%s %s %s\r\n", req->method,req->path,req->protocol);
    sprintf(line,"%s %s %s\r\n", req->method,req->path,req->protocol);
    write(serverfd, line, strlen(line));
    while ( (r=readBuffer(c_reader, line)) > 0){
        (void) write(serverfd, line, r);
        for(int i=0; i<r; i++)
            putchar(line[i]);
        if (strcmp(line, "\n") == 0 || strcmp(line, "\r\n") == 0)
            break;
        if (strncasecmp(line, "Content-Length:", 15) == 0)
            cl = atol(&line[15]);
    }

    if (cl > 0)
        while( (cl -= ( r=readBuffer(c_reader, line) )) > 0 ){
           // if (byte == EOF)
           //     continue;
            printf("%s", line);
            write(serverfd, line, r);
        }
    cl = -1;
    fflush(stdout);
    //fflush(s_wfd);

    printf("%% RESPONSE %s %%\n", req->host);
    while(((r=readBuffer(s_reader, line)) > 0)){
        (void) write(clientfd, line, r);
        printf("    %s",line);
        if (strcmp(line, "\n") == 0 || strcmp(line, "\r\n") == 0)
            break;
        if (strncasecmp(line, "Content-Length:", 15) == 0)
            cl = atol(&line[15]);
    }
    int total = 0, clcopy = cl;
    s_reader->delim = READER_NO_DELIM;
    s_reader->chunkSize = 1;
    if (cl > 0)
    while( ( (r=readBuffer(s_reader, line) )) >0 ){
        //if ((byte = getc(s_rfd)) == EOF)
        //    continue;
        //                putchar(byte);
        printf("%d\n",cl );
        write(clientfd, line,r);
        total += r;
    }
    total+=r;
    printf("\n                total content length::%d/%d\n", total, clcopy);
    
    fflush(stdout);
    
    freeHTTPRequest(req);
    closeReader(c_reader);
    closeReader(s_reader);
    return 0;
}

void proxyhttps(int clientfd, int serverfd){
    SSL_Connection* ssl_c;
    SSL_Connection* ssl_s = SSL_Connect(serverfd);
    
    int r=0;
    char buf[1024];
    
    printf("got new connection.  \n");

    int offset = 1;
    printf("%% CLEAR PROXY REQUEST %%\n");
    if( (r = read(clientfd, buf, 1000)) > 0){
        if (offset > 1024){
            printf("payload exceded allocated space\n");
            exit(4);
        }
        buf[r] = '\0';
        offset += r;
        printf("%s", buf);
    }
    printf("Connection Established.\n");
    char *inject = "HTTP/1.0 200 Connection established\r\n\r\n";
    write(clientfd, inject, strlen(inject));

    printf("SSL connecting . . .\n");

    ssl_c = SSL_Accept(clientfd);

    printf("SSL handshake finished. Reading content.\n");
    printf("%% SSL REQUEST %%\n");

    if((r = SSL_read(ssl_c->socket, buf, 1024)) > 0){
        if (offset > 1024){
            printf("payload exceded allocated space\n");
            exit(4);
        }
        printf("%s", buf);
        SSL_write(ssl_s->socket, buf, r);

    }

    fflush(stdout);
    // send response
    printf("%% SERVER RESPONSE %%\n");
    offset=1;
    while ((r=SSL_read(ssl_s->socket, buf, 1023))>0){
        
        offset++;
        SSL_write(ssl_c->socket, buf, r);
        buf[r] = '\0';
        printf("%s", buf);
    }
    printf("closing connection\n");
    SSL_Close(ssl_s);
    SSL_Close(ssl_c);

}


/*
int proxyHTTPS(HTTPRequest* req, struct SSLConnection* ssls, int clientfd, int serverfd){
    // Establish SSL handshake with both sides
    struct SSLConnection *sslc;
    struct SSLConnection __sslc;
    sslc = &__sslc;
    sslc->sslHandle = SSL_new(CTX);
    //if (! SSL_set_fd(ssls->sslHandle, serverfd)){
    //    ERR_print_errors_fp(stdout);
    //    exit(3);
    //}
    //if (! SSL_connect(ssls->sslHandle)){
    //    ERR_print_errors_fp(stdout);
    //    exit(3);
    //}
    char *inject = "HTTP/1.0 200 Connection established\r\n\r\n";
    char buf[HTTP_BUF_SIZE];
    int r;
    int off=0;
    printf("%% CLEAR HOST REQUEST %%\n");
    if((r = read(clientfd, buf, 1000))>0){
        buf[r]='\0';
        printf("    ");
        for (int i=0; i<r; i++){
            putchar(buf[i]);
            if (buf[i] == '\n')
                printf("    ");
        }
    }
    write(clientfd, inject, strlen(inject));
    printf("%s", inject);  
    SSL_set_fd(sslc->sslHandle, clientfd);
    SSL_accept(sslc->sslHandle);
    printf("SSL connected.\n");
    printf("%% SSL REQUEST %%\n");
    off = 1;
    while((r = SSL_read(sslc->sslHandle, &buf[off++], 1)) > 0){
        if (off > 1024){
            printf("payload exceded allocated space\n");
            exit(4);
        }
        printf("%c\n", buf[off-1]);
        if (buf[off-1] == '\n'){
            buf[off] = '\0';
            printf("    %s", &buf[1]);
            //if (strncasecmp(&buf[1], "connect",7) == 0)
            //    connected = 1;
            //else if (strncasecmp(&buf[1], "get", 3) == 0)
            //    timeToSend=1;
            //else
            if ( buf[off-2] == '\n' || buf[off-2] == '\r')
                break;
            off = 1;
        }

    }
    fflush(stdout);


    printf("%% SERVER RESP %%");
    int offset=1,cl=0;
    while( (r = SSL_read(ssls->sslHandle, &buf[offset++],1)) > 0 ){
        if (offset > 1024){
            printf("payload exceded allocated space\n");
            exit(4);
        }
        if (buf[offset-1] == '\n'){
            buf[offset] = '\0';
            printf("    %s", &buf[1]);
            //       SSL_write(sslc->sslHandle, &buf[1], offset-1);
            if (strncasecmp(&buf[1], "Content-length:", 15) == 0)
                cl=atol(&buf[16]);
            else if ( buf[offset-1]=='\n' &&(buf[offset-2] == '\n' || buf[offset-2] == '\r'))
                break;
            offset = 1;
        }
    }
    if (cl){
        while(cl-- && (r = SSL_read(ssls->sslHandle, &buf[0], 1))){
            SSL_write(sslc->sslHandle, &buf[0], 1);
        }
    }
    // Close connection
    if (sslc->sslHandle != (SSL*) 0){
        SSL_shutdown(sslc->sslHandle);
        SSL_free(sslc->sslHandle);
    }
    if (sslc->sslContext != (SSL_CTX*) 0)
        SSL_CTX_free(sslc->sslContext);
    return 0;
}*/
/*
   int proxyHTTPS(HTTPRequest* req, FILE* c_rfd, FILE* c_wfd, FILE* s_rfd, FILE* s_wfd){
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
*/


