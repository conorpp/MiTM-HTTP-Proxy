/*
    Server
*/
#include "utils.h"
#include "http.h"
#include "ssl.h"
#include "regex.h"
#include "string.h"
#include "proxy.h"



int proxyHttp(int clientfd, int (*editCallback)(HttpResponse*));
int editPage(HttpResponse* res);

int replaceFunc(const char* string, Range* r){
    // Limit the matches
    static int limit = -2;
    if (limit == -2)
        limit = Prox.options.count;
    int offset = 0;
    if (Prox.match(string, r, Prox.regex) != 0)
        return -1; // no more matches!
    LogContent(LOG_DEBUG|LOG4, string + r->start, r->end - r->start);
    if (!r->start && !r->end)
        return -1;

    switch (Prox.options.position){
        case CL_BEFORE:
            offset = r->end - r->start;
            r->end = (r->start);
        break;
        case CL_REPLACE:
        break;
        case CL_AFTER:
            r->start = (r->end);
        break;
        case CL_APPEND:
            r->start = (r->end -= Prox.options.offset);
            offset = Prox.options.offset;
        break;
        case CL_PREPEND:
            offset = r->end;
            if (Prox.regex->rEndTerm != (char*) 0){
                char* index = strstr(string + r->start, Prox.regex->rEndTerm);
                if (index != (char*) 0){
                    r->start += (int)(index - string - r->start + 1);
                }
            }
            r->end = r->start;
            offset -= r->start;

            //exit(1);
        break;
    }
    printf("\ninserting at %d:%d\n", r->start, r->end);
    write(fileno(stdout), string + r->start, 200);
    // Stop matching if limit reaches.
    if (limit) limit--;
    else return -1;

    // return additional offset for start of next match.
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
    if (Prox.files != (char**)0)
        res->store->content = insertFiles(replaceFunc,
            res->store->content, res->store->contentLength,
            &res->store->contentLength, Prox.files, Prox.filenum);
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

    // generate the settings
    setProxSettings(argc, argv);

    // Prepare openSSL for any HttpS connections
    SSL_Init(Prox.ssl.certfile, Prox.ssl.privfile);

    // set up handler to kill zombie processes
    signal(SIGCHLD, sigchldHandler);

    // set up handler for timeouts
    signal(SIGALRM, timeoutHandler);

    sockfd = Listen(NULL, Prox.port);

    Log(LOG_DEBUG|LOG1,"Proxy listening on %s\n", Prox.port);
#ifdef NOFORK
    Log(LOG_DEBUG|LOG3,"NOFORK\n");
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

int proxyHttp(int clientfd, int (*editCallback)(HttpResponse*)){
    int s, serverfd;
    HttpRequest req;
    HttpResponse res;
    HttpWrap(&req, clientfd, HTTP_REQ);

    char line[10000];

    alarm(Prox.options.timeout);
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
    alarm(Prox.options.timeout);
    if (req.method == (char*)0 || strncasecmp(req.method,"CONNECT",7)==0){
        Log(LOG_DEBUG|LOG3,"--junk request received.\n");
        req.SSL = (SSL_Connection*)0;
        memset(&res, 0, sizeof(HttpResponse));
        goto done;
    }
    Log(LOG_DEBUG|LOG1,"\n-%%- Request(%d) -%%-\n", clientfd);

    // Write the request
    sprintf(line, "%s %s %s\r\n", req.method, req.path, req.protocol);
    Log(LOG_REQ_HEADER,line);
    HttpWrite(&res, line, strlen(line));
    Log(LOG_DEBUG|LOG1,"\n--%% writing headers\n");

    writeHttpHeaders(&res, req.header);
    printHttpHeaders(&req.header, LOG_REQ_HEADER);

    // write any content if there was any
    if (req.store->contentLength){
        Log(LOG_DEBUG|LOG1,"--%% writing content %d\n", req.store->contentLength);
        HttpWrite(&res, req.store->content, req.store->contentLength);
        printf("LOGGING HTTP REQ DATA %s\n", req.store->content);

        LogContent(LOG_REQ_DATA,req.store->content,
                            req.store->contentLength);
    }

    // Retrieve response
    Log(LOG_DEBUG|LOG1,"\n-%%- RESPONSE(%d) -%%-\n", clientfd);
    alarm(Prox.options.timeout);
    while( (HttpRead(&res)) > 0 ){
        do {
           s = HttpParse(&res, &res.header, res.store);
           if (s == E_reset)
               HttpRewind(&res, HTTP_RES);
        }while(HTTP_IS_PARSING(s));
        if (s == E_finished)
            break;
    }
    alarm(Prox.options.timeout);
    // status
    sprintf(line, "%s %d %s\r\n", res.protocol, res.status, res.comment);
    HttpWrite(&req, line, strlen(line));
    Log(LOG_RES_HEADER,"%s", line);

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
    printHttpHeaders(&res.header, LOG_RES_HEADER);
    // content
    HttpWrite(&req, res.store->content, res.store->contentLength);
    LogContent(LOG_RES_DATA|LOG3, res.store->content,
                            res.store->contentLength);
    done:
    alarm(0);
    freeHttpRequest(&req);
    freeHttpResponse(&res);
    close(serverfd);

    return 0;
}
