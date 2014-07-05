/*
    Server
*/

#include "utils.h"
#include "tcp.h"
#include "http.h"
#include "ssl.h"

int proxyHttp(int clientfd);


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
        
        if (newfd == -1){
            perror("accept"); continue;
        }
#ifndef NOFORK
        if (fork() == 0){       //   parent
            close(sockfd);
            proxyHttp(newfd);
            close(newfd);
            exit(0);
        }else{                  //   parent
            close(newfd);
        }
#else
        proxyHttp(newfd);
        close(newfd);
#endif
    }

    return 0;
}

int HttpParse(void* http, HttpHeader** header, HttpStore *http_store){
    char* httpbuf = http_store->buf;
    int l;
    if (http_store->state == E_connect){
        http_store->state = E_readHeader;
    }
    switch(http_store->state){
        case E_reReadMethod:
            printf("--reReading method\n");
        case E_readMethod:
        case E_readStatus:
            //printf("--Reading method\n");
            if (http_store->state == E_readStatus)
                http_store->offset = HttpParseStatus((HttpResponse*)http, httpbuf);
            else
                http_store->offset = HttpParseMethod((HttpRequest*)http, httpbuf);
            
            http_store->headers = httpbuf + http_store->offset;
            //printf("--header start is ::\n");\

            //write(fileno(stdout), http_store->headers, 50);
            //HttpRequest* req = (HttpRequest*) http;
            //printf("reading method. %s %s %s\n",
            //        req->method, req->path, req->protocol);
            if (http_store->state == E_readMethod)
                return (http_store->state = E_connect);
            else
                return (http_store->state = E_readHeader);
                
        break;
        case E_readMoreHeader:
            http_store->state = E_readHeader;
        case E_readHeader:
            httpbuf = http_store->buf + http_store->offset;
            http_store->headerLength = 0; 
            // Parse all available headers.
            while((l = HttpParseHeader(header, httpbuf)) > 0){
                if (http_store->offset > http_store->length){
                    printf("--EXCEEDING STORE SIZE %d\n", http_store->length);
                    exit(0);
                }
                http_store->offset += l;
                http_store->headerLength += l;
                httpbuf = http_store->buf + http_store->offset;

            }
            //printHttpHeaders(header);
            if (l == 0){
                // Req/Res is finished unless there is content.
                http_store->headerLength += 2;
                http_store->offset += 2;
//                write(fileno(stdout), http_store->headers, http_store->headerLength);
//                printf("---------+\n");
//                http_store->content = http_store->buf + http_store->offset;
                HttpHeader* h = getHttpHeader(*header, HTTPH_CL);
                if (h != (HttpHeader*) 0){
                    http_store->contentLength = atol(h->data);
                    http_store->state = http_store->contentLength ? E_readContent : E_finished;

                }else if((h = getHttpHeader(*header, HTTPH_T_ENCODING)) != (HttpHeader*) 0){
                    if (strncasecmp(h->data, "chunked", 7) == 0){
                        http_store->state = E_readChunks;
                    }else
                        http_store->state = E_finished;
                }else
                    http_store->state = E_finished;
                
                saveHttpHeaders(http_store);

                break;
            }else{
                // Still waiting for headers.
                printf("---Reading more of header\n");
                http_store->state = E_readMoreHeader;  
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
                saveHttpContent(http_store, http_store->buf + http_store->offset,
                                                    http_store->contentLength);
                http_store->state = E_finished;
            }else{
            //    printf("--E_readContent-continue\n");
                http_store->state = E_continue;
            }
        break;
        case E_readMoreChunks:
            http_store->state = E_readChunks;
        case E_readChunks:
            httpbuf = http_store->buf+http_store->offset;
            while( (l=readChunk(http_store, httpbuf)) > 0 ){
                http_store->offset += l;
                httpbuf += l;
                printf("got %d chunks\n",l);
            }

            if (l == 0){
                http_store->state = E_finished;
            }
            else{
                printf("---need to read more chunks");
                http_store->state = E_readMoreChunks;
            }
        break;
    }
    return http_store->state;
}

int proxyHttp(int clientfd){
    int s, serverfd;
    HttpRequest req;
    HttpResponse res;
    HttpWrap(&req, clientfd, HTTP_REQ);

    char line[10000];
    
    while ((HttpRead(&req)) > 0){
        do{
            s = HttpParse(&req, &req.header, req.store);
            if (s == E_connect){
                serverfd =  Connect(req.host, req.port);
                HttpWrap(&res, serverfd, HTTP_RES);
                if (req.is_ssl){
                    SSLWrap(&req, SSL_ACCEPT | HTTP_REQ);
                    SSLWrap(&res, SSL_CONNECT | HTTP_RES);
                    s = req.store->state = E_reReadMethod;
                }

            }
        }while(HTTP_IS_PARSING(s));
            
        if (s == E_finished){
            break;
        }
    }
    if (req.method == (char*)0 || strncasecmp(req.method,"CONNECT",7)==0){
        printf("--junk request received.\n");
        req.SSL = (SSL_Connection*)0;
        memset(&res, 0, sizeof(HttpResponse));
        goto done;
    }
    printf("\n-%%- Request(%d) -%%-\n", clientfd) ;
    
    // Write the request
    
    sprintf(line, "%s %s %s\r\n", req.method, req.path, req.protocol);
    write(fileno(stdout), line, strlen(line));
    HttpWrite(&res, line, strlen(line));
    printf("\n--%% writing headers\n");
    
    writeHttpHeaders(&res, req.header);

    // write any content if there was any
    if (req.store->contentLength){
        printf("--%% writing content\n");
        HttpWrite(&res, req.store->content, req.store->contentLength);
        write(fileno(stdout), req.store->content, req.store->contentLength);
    }

    // Retrieve response
    printf("\n-%%- RESPONSE(%d) -%%-\n", clientfd);
    while( (HttpRead(&res)) > 0 ){
        do {
           s = HttpParse(&res, &res.header, res.store);
        }while(HTTP_IS_PARSING(s));
        if (s == E_finished)
            break;
    }
  
    // status
    sprintf(line, "%s %d %s\r\n", res.protocol, res.status, res.comment);
    HttpWrite(&req, line, strlen(line));
    printf("%s", line);
    // headers
    if (res.store->contentLength){
        char num[12];
        sprintf(num,"%d", res.store->contentLength);
        deleteHttpHeader(&res.header, HTTPH_CL);
        deleteHttpHeader(&res.header, HTTPH_T_ENCODING);
        addHttpHeader(&res.header,"Content-length", num);
    }
    writeHttpHeaders(&req, res.header);
 
    // content
    HttpWrite(&req, res.store->content, res.store->contentLength);
    
    done:
    freeHttpRequest(&req);
    freeHttpResponse(&res);
    close(serverfd);

    return 0;
}


