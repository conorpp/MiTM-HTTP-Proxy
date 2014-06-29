#include "http.h"

int HttpRead(void* http){
    HttpTransaction* T = (HttpTransaction*) http;
    int r=0, nbytes;
    char* buffer;
    printf("---checking buffer size\n");
    while ((nbytes = T->store->size - T->store->length) < 4){
        T->store->size *= 4;
        T->store->buf = realloc(T->store->buf, T->store->size);
        printf("--Store: memory exceded. 4x more space made.\n");
        printf("--space: %d kb\n", T->store->size / (1<<10));
    }
    printf("---reading up to %d bytes\n", nbytes);
    buffer = T->store->buf + T->store->length;
    if (T->is_ssl){
        while( (r += SSL_read(T->SSL->socket, buffer, nbytes))>0){
            if (r > 0) break;
        }
    }
    else
        r = read(T->socket, buffer, nbytes);
    T->store->length += r;
    
    return r;
}
void HttpWrite(void* http, void* buffer, int num){
    int ec=0;
    HttpTransaction* T = (HttpTransaction*) http;
    
    if (T->is_ssl){
        while( (ec += SSL_write(T->SSL->socket, buffer, num))<num);
    }
    else
        ec = write(T->socket, buffer, num);

    if (ec < 0)
        die("HttpWrite: write or SSL_write failed.");
   
}

void dumpStore(HttpStore* http_store){
    
    write(fileno(stdout), http_store->buf, http_store->length);
    fflush(stdout);
}

void HttpWrap(void* http, int sockfd, int flags){
    memset(http,  0, sizeof(HttpTransaction));
    HttpTransaction* T = (HttpTransaction*) http;
    T->socket = sockfd;
    T->store = newHttpStore(flags);
}

HttpStore* newHttpStore(int flags){
    char* buffer = malloc(STORE_SIZE);
    HttpStore* S = malloc(sizeof(HttpStore));
    memset(S, 0, sizeof(HttpStore));
    S->buf = buffer;
    if (IS_HTTP_REQ(flags) && !IS_HTTPS(flags))
        S->state = E_readMethod;
    else if (IS_HTTP_REQ(flags) && IS_HTTPS(flags))
        S->state = E_reReadMethod;
    else if (IS_HTTP_RES(flags))
        S->state = E_readStatus;
    S->headers = buffer;
    S->content = buffer;
    S->size = STORE_SIZE;

    return S;
}

void freeHttpStore(HttpStore* S){
    if (S != (HttpStore*) 0){
        if (S->buf != (char*) 0)
            free(S->buf);
        free(S);
    }
}

//int store(HttpStore* S, char* data, int length, int flags){
//    if (S->length + length > STORE_SIZE)
//        die("store:  memory exceeded.");
//    memmove(buffer+S.length, data, length);
//    return (S.length += length);
//}

void printHttpHeaders(HttpHeader **header){
    HttpHeader** tmp = header;
    printf("\n");
    while(*tmp != (HttpHeader*)0){
        printf("%s: %s\n", (*tmp)->header, (*tmp)->data);
        tmp = &((*tmp)->next);
    }
    printf("\n");
}



int HttpParseHeader(HttpHeader** header, char* httpbuf){
    static char headertype[100], data[10000];
    int ec;

    if (
            strncasecmp(httpbuf, "\r\n", 2) == 0 ||
            strncasecmp(httpbuf, "\r\n\r\n", 4) == 0 
    //        strlen(httpbuf) == 0
       ){
        return 0;
    }

    ec = sscanf(httpbuf, "%100[^: ] %*[: ] %10000[^\r\n]",
            headertype, data);
    if (ec == 2){
        addHttpHeader(header, headertype, data);
        printf("added header %s: %s\n", headertype,data);
        return (strlen(headertype) + strlen(data) + 4);
    }else{
            printf("--leftover str:%s\n", httpbuf);
            printf("--bytes: ");
            return -1;
            //exit(4);
            while(*httpbuf)
                printf("%c", *httpbuf++);
            fflush(stdout);
    }

    return -1;
}

void getHttpHeaderType(HttpHeader* head, char *str){
    static char* headerStrs[] = {
        "Host",
        "Accept-Encoding",
        "Content-length",
        "Transfer-Encoding"
    };
    static int headerTypes[] = {
        HTTPH_HOST,
        HTTPH_A_ENCODING,
        HTTPH_CL,
        HTTPH_T_ENCODING
    };
    static int count = 4;
    for(int i=0; i<count; i++){
        if (strncasecmp(
            headerStrs[i], str, strlen(str)
            )==0){
            head->type = headerTypes[i];
            head->header = headerStrs[i];
            return;
        }
    }
    head->type = HTTPH_UNKNOWN;
    int l = strlen(str)+1;
    head->header = malloc(l);
    memmove(head->header, str, l);
}

void addHttpHeader(HttpHeader** first, char* type, char* data){
    HttpHeader** tmp = first;
    if (*tmp != (HttpHeader*)0){
      while((*tmp)->next != (HttpHeader*) 0){
        tmp = &((*tmp)->next);
      }
      (*tmp)->next = malloc(sizeof(HttpHeader));
      tmp = &((*tmp)->next);
    }
    else{
        *tmp = malloc(sizeof(HttpHeader));
    }
    getHttpHeaderType(*tmp, type);
    (*tmp)->length = strlen(data)+1;
    (*tmp)->data = malloc( (*tmp)->length);
    (*tmp)->next = (HttpHeader*)0;
    memmove((*tmp)->data, data, (*tmp)->length);
}

HttpHeader* getHttpHeader(HttpHeader* first, int type){
    HttpHeader* tmp = first;
    while(tmp != (HttpHeader*) 0){
        if (tmp->type == type)
            return tmp;
        tmp = tmp->next;
    }
    return (HttpHeader*) 0;
}

void freeHttpHeaders(HttpHeader** first){
    HttpHeader **tmp, **last;
    tmp = first;
    while(*tmp != (HttpHeader*)0){
        last = tmp;
        tmp = &((*tmp)->next);
        if ((*last)->data != (char*) 0)
            free((*last)->data);
        if ((*last)->type == HTTPH_UNKNOWN && (*last)->header != (char*) 0)
            free((*last)->header);
        free(*last);
        *last = (HttpHeader*) 0;
    }
}

int HttpParseMethod(HttpRequest* req, const char* str){
    if (sizeof str > HTTP_BUF_SIZE){
        printf("Http request str is longer than max %d bytes", HTTP_BUF_SIZE);
        exit(3);
    }
    static char *method = &HTTP_BUF[0];
    static char *url = &HTTP_BUF[101];
    static char *protocol = &HTTP_BUF[10102];
    int size, total = 0;
    if((sscanf(str, "%100[^ ] %10000[^ ] %100[^ \r\n]", method, url, protocol))!=3){
        printf("%s\n\n",str);
        die("invalid Http request");
        
    }
    req->method = (char *) malloc( (size = strlen(method)+1) );
    memmove(req->method, method, size);
    total += size;

    req->url = (char *) malloc( (size = strlen(url)+1) );
    memmove(req->url, url, size);
    total += size;

    req->protocol = (char *) malloc( (size = strlen(protocol)+1) );
    memmove(req->protocol, protocol, size);
    total += size;

    if (!req->is_ssl){
        parseURL(req->url, &req->host, &req->path, &req->port, &req->is_ssl);

        if (strncasecmp(req->method, "CONNECT", 7) == 0){
            req->is_ssl = 1;
        }
    }else{
        req->path = req->url;
    }
    fflush(stdout);
    return total + 1; // two spaces, \r, \n
}



int HttpParseStatus(HttpResponse* res, const char* str){
    if (sizeof str > HTTP_BUF_SIZE){
        printf("Http request str is longer than max %d bytes", HTTP_BUF_SIZE);
        exit(3);
    }
    static char *protocol = &HTTP_BUF[0];
    static char *comment = &HTTP_BUF[101];

    int size, total = 0;
    if(sscanf(str, "%100s %d %1000[^\r\n]", protocol, &res->status, comment)!=3){
       printf("%s\n",str); 
        die("invalid Http response");
    }
    res->comment = (char *) malloc( (size = strlen(comment)+1) );
    memmove(res->comment, comment, size);
    total += size;

    res->protocol = (char *) malloc( (size = strlen(protocol)+1) );
    memmove(res->protocol, protocol, size);
    total += size;

    return total+2+3; // \r + \n, 2-3 spaces
}


void parseURL(const char* url, char** host, char** path, int* port, int* ssl){

    int offset = 0;
    int size;
    
    if (strncasecmp(url, "http://", (offset=7)) == 0)
        *ssl = 0;
    else if (strncasecmp(url, "https://", (offset=8)) == 0)
        *ssl = 1;
    else 
        offset = 0;
    if (sscanf(&url[offset], "%[^/:]", HTTP_BUF) != 1){
        memmove(HTTP_BUF, url, strlen(url)+1);
    }

    offset += (size = strlen(HTTP_BUF)+1);
    *host = (char*) malloc(size);
    memmove(*host, HTTP_BUF, size);

    if (sscanf(&url[offset-1], ":%d%s", port, HTTP_BUF) != 2){
        if (sscanf(&url[offset-1], ":%d", port) != 1){
            if (sscanf(&url[offset-1], "%s", HTTP_BUF) != 1)
                sprintf(HTTP_BUF, "/");
            *port = 80;
        }
    }
    if (*port == 443) *ssl = 1;
    size = strlen(HTTP_BUF)+1;
    *path = (char*) malloc(size);
    memmove(*path, HTTP_BUF, size);
}

void freeURL(char* host, char* path){
    if (host != (char*) 0)
        free(host);
    if (path != (char*) 0)
        free(path);
}

void freeHttpRequest(HttpRequest* req){
    printf("freeing req\n");
    if (req->method != (char*) 0)
        free(req->method);
    if (req->url != (char*) 0)
        free(req->url);
    if (req->protocol != (char*) 0)
        free(req->protocol);
    printf("freeing req ssl %x\n", req->SSL);
    if (req->SSL != (SSL_Connection*) 0)
        SSL_Close(req->SSL);
    if (req->is_ssl)
        req->path = (char*) 0;
    printf("freeing req store, url, headers\n");
    freeHttpStore(req->store);
    freeURL(req->host, req->path);
    freeHttpHeaders(&req->header);
}

void freeHttpResponse(HttpResponse* res){
    printf("freeing res\n");
    if (res->comment != (char*) 0)
        free(res->comment);
    if (res->protocol != (char*) 0)
        free(res->protocol);

    if (res->SSL != (SSL_Connection*) 0)
        SSL_Close(res->SSL);
    freeHttpStore(res->store);
    freeHttpHeaders(&res->header);
}




