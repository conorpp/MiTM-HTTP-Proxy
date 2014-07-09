/*
    Server
*/
#include "utils.h"
#include "tcp.h"
#include "http.h"
#include "ssl.h"
#include "regex.h"
#include "string.h"
#include "commandline.h"
#include "proxy.h"

int proxyHttp(int clientfd, int (*editCallback)(HttpResponse*));
int editPage(HttpResponse* res);

int replaceFunc(const char* string, Range* r){
    // Check if theres a match
    if (matchRegex(string, r, Prox.regex) != 0)
        return -1; // no more matches!
         printf("replacing:\n");
        fflush(stdout);
        write(fileno(stdout), string + r->start, r->end-r->start);
        printf("\n");
    int offset = 0;
    switch (Prox.options.position){
        case CL_BEFORE:
            offset = r->end - r->start;
            r->end = (r->start += 0);
        break;
        case CL_REPLACE:
        break;
        case CL_AFTER:
            r->start = (r->end -= 0);
        break;
    }
    return offset;
}

int userEditPage(HttpResponse* res){
    if (Prox.regex == (Regex*)0){
        return 0;
    }
    char *tmp = res->store->content;
    
    // Replace with string
    if (Prox.replaceString != (char*)0){
        res->store->content = replaceAll(replaceFunc, res->store->content,
            res->store->contentLength, &res->store->contentLength,
            Prox.replaceString);
    }
    if (tmp != (char*)0 && tmp != res->store->content)free(tmp);
    tmp = res->store->content;
    // replace with files
    printf("Prox files**: %x\n", (int)Prox.files);
    if (Prox.files != (char**)0)
        res->store->content = insertFiles(replaceFunc, 
            res->store->content, res->store->contentLength, 
            &res->store->contentLength, Prox.files, 1);
    if (tmp != (char*)0 && tmp != res->store->content) free(tmp);
    return 0;
}

int main(int argc, char *argv[]){
    
    if (argc<2){
        Help();
        exit(1);
    }

    struct sockaddr_storage their_addr;
    socklen_t slen;
    int sockfd, newfd;
    
    // Prepare openSSL for any HttpS connections
    setProxSettings(argc, argv);
    SSL_Init(Prox.ssl.certfile, Prox.ssl.privfile);
    generateRegexes();

    sockfd = Listen(NULL, Prox.port);
    
    printf("Proxy listening on %s\n", Prox.port);
#ifdef NOFORK
    printf("NOFORK\n");
#endif
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
            proxyHttp(newfd, userEditPage);
            close(newfd);
            exit(0);
        }else{                  //   parent
            close(newfd);
        }
#else
        proxyHttp(newfd, userEditPage);
        close(newfd);
#endif
    }

    return 0;
}


int editPage(HttpResponse* res){
    char *tmp = res->store->content;
    
    // Replace all links
    res->store->content = replaceAll(findLink, res->store->content,
            res->store->contentLength, &res->store->contentLength,
            "http://youtu.be/dQw4w9WgXcQ");
    if (tmp != (char*)0 && tmp != res->store->content)free(tmp);
    char *files[] = {"gravityscript.html"};
    tmp = res->store->content;
    res->store->content = insertFiles(findHeadEnd, 
        res->store->content, res->store->contentLength, 
        &res->store->contentLength, files, 1);
    if (tmp != (char*)0 && tmp != res->store->content) free(tmp);
    // Add files
    return 0;
}

int proxyHttp(int clientfd, int (*editCallback)(HttpResponse*)){
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
 
    HttpHeader* H = getHttpHeader(res.header, HTTPH_CT);

    // Decode gzip to get clear text
    if (H != (HttpHeader*) 0){
        // todo: change to indexOf functions
        if (strstr(H->data, "text/html")!= (char*)0){
            H = getHttpHeader(res.header, HTTPH_C_ENCODING);
            if(H != (HttpHeader*) 0){
                if (strstr(H->data, "gzip") != (char*)0){
                    decodeGzip(&res.store->content, &res.store->contentLength);
                    deleteHttpHeader(&res.header, HTTPH_C_ENCODING);
                }
            }
            editCallback(&res);
        }
    }
    
    if (res.store->contentLength){
        char num[12];
        sprintf(num,"%d", res.store->contentLength);
        deleteHttpHeader(&res.header, HTTPH_CL);
        deleteHttpHeader(&res.header, HTTPH_T_ENCODING);
        addHttpHeader(&res.header,"Content-length", num);
    }
    // headers
    writeHttpHeaders(&req, res.header);
    // content
    HttpWrite(&req, res.store->content, res.store->contentLength);
    //if (clearText)
    //    write(fileno(stdout), res.store->content, res.store->contentLength);
    done:
    freeHttpRequest(&req);
    freeHttpResponse(&res);
    close(serverfd);

    return 0;
}


