/*
    Server
*/

#include "utils.h"
#include "tcp.h"
#include "http.h"
#include "ssl.h"

struct SSLConnection {
    int socket;
    SSL *sslHandle;
    SSL_CTX *sslContext;
};


int proxyHTTP(int clientfd);
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
    
    // Prepare for any ssl connections
    SSL_Init(argv[2], argv[3]);
    printf("Proxy listening on %s\n", argv[1]);
    
    sockfd = Listen(NULL, argv[1]);
    
    while(1){
        
        slen = sizeof their_addr;
        newfd = accept(sockfd, (struct sockaddr *)&their_addr, &slen);
        printf("--New Connection--\n");
        
        if (newfd == -1){
            perror("accept"); //continue;
        }
        
        if (fork() == 0){       // child process 
            close(sockfd);
            
            
            if (0){
            }else{
                printf("PROXYING HTTP \n" );
                proxyHTTP(newfd);
            }
            close(newfd);
            //close(serverfd);
            exit(0);
        }else{//   parent
            close(newfd);
        }
    }
    fflush(stdout);

    return 0;
}
int parseHTTP(void* http, HTTPHeader** header, HTTPStore *http_store){
    //static char headertype[1000], data[1000];
    //int ec;
    char* httpbuf = http_store->buf;
    int l;
    if (http_store->state == E_connect)
        http_store->state = E_readHeader;
    switch(http_store->state){
        case E_readMethod:
            // Parse the first line in HTTP Request
            http_store->offset = parseHTTPMethod((HTTPRequest*)http, httpbuf);
            http_store->headers = &httpbuf[http_store->offset];
            return (http_store->state = E_connect);
        break;
        case E_readStatus:
            // Parse the first line in HTTP Response
            http_store->offset = parseHTTPStatus((HTTPResponse*)http, httpbuf);
            return (http_store->state = E_readHeader);
        break;
        case E_readHeader:
            httpbuf = &http_store->buf[http_store->offset];
            // Parse all available headers.
            while((l = parseHTTPHeader(header, httpbuf)) > 0){
                http_store->offset += l;
                httpbuf = &http_store->buf[http_store->offset];
            }
            if (l == 0){
                // Req/Res is finished unless there is content.
                http_store->headerLength = &httpbuf[http_store->offset] - http_store->headers;
                http_store->content = &httpbuf[http_store->offset];
                HTTPHeader* h = getHTTPHeader(*header, HTTPH_CL);
                if (h == (HTTPHeader*) 0)
                    http_store->state = E_finished;
                else{
                    http_store->contentLength = atol(h->data);
                    http_store->state = http_store->contentLength ? E_readContent : E_finished;
                }
                break;
            }else{
                // Still waiting for headers.
                http_store->state = E_readHeader;  
            }
        break;
        case E_readContent:
            // Check if the content length has been met.
            if (http_store->length - http_store->offset >= http_store->contentLength){
                http_store->state = E_finished;
            }
        break;
    }
    return http_store->state;
}

int proxyHTTP(int clientfd){
    int r, s;
    HTTPRequest req;
    HTTPResponse res;
    memset(&req,  0, sizeof(HTTPRequest));
    memset(&res,  0, sizeof(HTTPResponse));
    int serverfd;
    char line[10000];
    HTTPStore* http_store;
    
    http_store = store(NULL, 0, HTTP_REQ);
    
    while ((r = read(clientfd, line, 9999)) > 0){
        (void) store(line, r, 0);
        
        if (parseHTTP(&req, &req.header, http_store) == E_connect){
            serverfd = Connect(req.host, req.port);
        }
        if (parseHTTP(&req, &req.header, http_store) == E_finished)
            break;        

    }
    printf("\n-%%- Request -%%-\n") ;
    // Write the request
    sprintf(line, "%s %s HTTP/1.0\r\n", req.method, req.path);//, req.protocol);
    write(serverfd, line, strlen(line));
    write(fileno(stdout), line, strlen(line));

    // write custom headers
    HTTPHeader* H;
    for(H=req.header; H != (HTTPHeader*)0; H=H->next){
        switch(H->type){
            case -1://HTTPH_A_ENCODING:
                sprintf(line, "%s: deflate\r\n", H->header);    
            break;
            default:
                sprintf(line, "%s: %s\r\n", H->header, H->data);
            break;
        }
        write(fileno(stdout), line, strlen(line));
        write(serverfd, line, strlen(line));
    }

    // finish with empty line
    write(serverfd, "\r\n", 2);
    write(fileno(stdout), "\r\n", 2);
    
    // write any content if there was any
    write(serverfd, http_store->content, http_store->contentLength);
    write(fileno(stdout), http_store->content, http_store->contentLength);
    
    // Retrieve response
    printf("\n-%%- RESPONSE -%%-\n");
    http_store = store(NULL, 0, HTTP_RES);
    
    while( (r = read(serverfd, line, 9999)) > 0 ){
        (void) store(line, r, 0);

        s = parseHTTP(&res, &res.header, http_store);
        
        if (s == E_readHeader)
            s = parseHTTP(&res, &res.header, http_store);

        if (s == E_finished)
            break;
    }
    write(fileno(stdout), http_store->buf, http_store->length);
    write(clientfd, http_store->buf, http_store->length);
    
    freeHTTPRequest(&req);

    return 0;
}

void proxyhttps(int clientfd, int serverfd){
    SSL_Connection* ssl_c = (SSL_Connection*) 0;
    SSL_Connection* ssl_s = SSL_Connect(serverfd);
    
    int r=0,total=0;
    char buf[1024];
    
    int offset = 1;
    printf("%% CLEAR PROXY REQUEST %%\n");
    if( (r = read(clientfd, buf, 1000)) > 0){
        if (offset > 1024){
            printf("payload exceded allocated space\n");
            exit(4);
        }
        buf[r] = '\0';
        total = (offset += r);
        
        printf("%s", buf);
    }
    
    printf("Connection Established.\n");
    char *inject = "HTTP/1.0 200 Connection established\r\n\r\n";
    write(clientfd, inject, strlen(inject));

    printf("SSL connecting . . .\n");

    ssl_c = SSL_Accept(clientfd);

    printf("SSL handshake finished. Reading content.\n");
    printf("%% SSL REQUEST %%\n");
    total = 0;
    if((r = SSL_read(ssl_c->socket, buf, 1024)) > 0){
        if (offset > 1024){
            printf("payload exceded allocated space\n");
            exit(4);
        }
        total+=r;
        SSL_write(ssl_s->socket, buf, r);
        buf[r] = '\0';
        printf("%s (%d)", buf,r );

    }
    fflush(stdout);
    // send response
    if (!total) goto done;
    printf("%% SERVER RESPONSE %%\n");
    while ((r=SSL_read(ssl_s->socket, buf, 1023))>0){
        
        SSL_write(ssl_c->socket, buf, r);
        buf[r] = '\0';
        printf("%s", buf);
        if (buf[r-1]==EOF ) break;
    }
    done:
    printf("closing connection\n");
    SSL_Close(ssl_s);
    if (ssl_c != (SSL_Connection*) 0) SSL_Close(ssl_c);

}


/*
int proxyHTTPS(struct HTTPRequest* req, struct SSLConnection* ssls, int clientfd, int serverfd){
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
*/


