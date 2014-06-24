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


int proxyHttp(int clientfd);

void dumpStore(HttpStore*);

int main(int argc, char *argv[]){
    
    if (argc<4){
        die("you forgot port , cert , privkey\n");
    }

    struct sockaddr_storage their_addr;
    socklen_t slen;
    int sockfd, newfd;
    
    // Prepare openSSL for any HttpS connections
    SSL_Init(argv[2], argv[3]);
    
    sockfd = Listen(NULL, argv[1]);
    
    printf("Proxy listening on %s\n", argv[1]);
        
    while(1){
       
        //TODO make a header/helper function for this
        slen = sizeof their_addr;
        newfd = accept(sockfd, (struct sockaddr *)&their_addr, &slen);
        printf("--New Connection--\n");
        
        if (newfd == -1){
            perror("accept"); continue;
        }
        
        if (fork() == 0){       //   parent
            close(sockfd);
            proxyHttp(newfd);
            close(newfd);
            exit(0);
        }else{                  //   parent
            close(newfd);
        }
    }

    return 0;
}
int HttpParse(void* http, HttpHeader** header, HttpStore *http_store){
    //static char headertype[1000], data[1000];
    //int ec;
    char* httpbuf = http_store->buf;
    int l;
    if (http_store->state == E_connect)
        http_store->state = E_readHeader;
    switch(http_store->state){
        case E_reReadMethod:
        case E_readMethod:
            http_store->offset = HttpParseMethod((HttpRequest*)http, httpbuf);
            http_store->headers = &httpbuf[http_store->offset];
            HttpRequest* req = (HttpRequest*) http;
            //printf("reading method. %s %s %s\n",
            //        req->method, req->path, req->protocol);
            if (http_store->state == E_readMethod)
                return (http_store->state = E_connect);
            else
                return (http_store->state = E_readHeader);
                
        break;
        case E_readStatus:
            // Parse the first line in Http Response
            http_store->offset = HttpParseStatus((HttpResponse*)http, httpbuf);
            //printf("--reading status %d / %d\n", http_store->length - http_store->offset, http_store->contentLength );
            return (http_store->state = E_readHeader);
        break;
        case E_readHeader:
            httpbuf = &http_store->buf[http_store->offset];
            // Parse all available headers.
            
            //printf("reading headers %d / %d\n", http_store->length - http_store->offset, http_store->contentLength );
            while((l = HttpParseHeader(header, httpbuf)) > 0){
                http_store->offset += l;
                httpbuf = &http_store->buf[http_store->offset];
            }
            printHttpHeaders(header);
            if (l == 0){
                // Req/Res is finished unless there is content.
                http_store->headerLength = &httpbuf[http_store->offset] - http_store->headers;
                http_store->content = &httpbuf[http_store->offset];
                HttpHeader* h = getHttpHeader(*header, HTTPH_CL);
                if (h == (HttpHeader*) 0)
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
        case E_continue:
            http_store->state = E_readContent;
        case E_readContent:

            while( (l = http_store->length - http_store->offset) < 0 )
                http_store->offset -= l;
            
            printf("reading content %d / %d\n", 
                http_store->length - http_store->offset, 
                http_store->contentLength );
            // Check if the content length has been met.
            if (http_store->length - http_store->offset >= http_store->contentLength){
                http_store->state = E_finished;
                printf("--E_readContent-finished\n");
            }else{
                printf("--E_readContent-continue\n");
                http_store->state = E_continue;
            }
        break;
    }
    return http_store->state;
}

int proxyHttp(int clientfd){
    int s, serverfd;
    HttpRequest req;
    HttpResponse res;
    
    HttpWrap(&req, clientfd);

    char line[1000];
    HttpStore* http_store;
    
    http_store = store(NULL, 0, HTTP_REQ);
    printf("new connection\n"); 
    while ((HttpRead(&req, http_store)) > 0){
        if (HttpParse(&req, &req.header, http_store) == E_connect){
            serverfd =  Connect(req.host, req.port);
            HttpWrap(&res, serverfd);
            if (req.is_ssl){
                printf("PROXYING SSL\n");
                SSLWrap(&req, SSL_ACCEPT | HTTP_REQ);
                SSLWrap(&res, SSL_CONNECT | HTTP_RES);
                http_store = store(NULL, 0, HTTP_REQ);
                http_store->state = E_reReadMethod;
                continue;
            }
        }
        if (HttpParse(&req, &req.header, http_store) == E_finished)
            break;        

    }
    printf("\n-%%- Request -%%-\n") ;
    
    // Write the request
    sprintf(line, "%s %s %s\r\n", req.method, req.path, req.protocol);
    HttpWrite(&res, line, strlen(line));
    write(fileno(stdout), line, strlen(line));

    // write custom headers
    HttpHeader* H;
    for(H=req.header; H != (HttpHeader*)0; H=H->next){
        switch(H->type){
            case -1://Http_A_ENCODING:
                sprintf(line, "%s: deflate\r\n", H->header);    
            break;
            default:
                sprintf(line, "%s: %s\r\n", H->header, H->data);
            break;
        }
        HttpWrite(&res, line, strlen(line));
        printf("%s", line);
    }

    // finish header with empty line
    HttpWrite(&res, "\r\n", 2);
    write(fileno(stdout), "\r\n", 2);
    
    // write any content if there was any
    HttpWrite(&res, http_store->content, http_store->contentLength);
    write(fileno(stdout), http_store->content, http_store->contentLength);
    
    // Retrieve response
    printf("\n-%%- RESPONSE -%%-\n");
    http_store = store(NULL, 0, HTTP_RES);
    while( (HttpRead(&res, http_store)) > 0 ){
        //(void) store(line, r, 0);
        do {
           s = HttpParse(&res, &res.header, http_store);
        }while(s == E_readHeader || s == E_readContent);

        if (s == E_finished)
            break;
    }
    printf("DONE:\n");
    //printHttpHeaders(&res.header);
    write(fileno(stdout), http_store->buf, http_store->length);
    HttpWrite(&req, http_store->buf, http_store->length);
    
    freeHttpRequest(&req);
    freeHttpResponse(&res);

    return 0;
}


