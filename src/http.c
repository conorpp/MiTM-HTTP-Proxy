#include "http.h"

int HttpRead(void* http){
    HttpTransaction* T = (HttpTransaction*) http;
    int r=0, nbytes;
    char* buffer;
    while ((nbytes = T->store->size - T->store->length) < 4){
        T->store->size *= 4;
        T->store->buf = realloc(T->store->buf, T->store->size);
        printf("--Store: memory exceded. 4x more space made.\n");
        printf("--space: %d kb\n", T->store->size / (1<<10));
    }
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


void saveHttpContent(HttpStore* httpStore, char* buf, int length){
    while(httpStore->contentSpace - httpStore->contentOffset < length){
        printf("---allocating x4 space for chunk");
        httpStore->content = realloc(httpStore->content, 
                (httpStore->contentSpace*=4));
        printf(" (%d)\n", httpStore->contentSpace);
    }
    memmove(httpStore->content+httpStore->contentOffset, buf, length);
    httpStore->contentOffset += length;
}


int readChunk(HttpStore* httpStore, char* buf){
    int length;
    
    char *newline = strchr(buf, '\n');
    if ( sscanf(buf,"%x", &length) == 1){
        if (httpStore->offset + length > httpStore->length){
            printf("-- not enough has been read into the buffer for length %d\n", length);
            
            return -1;
        }
        saveHttpContent(httpStore, newline+1, length);
        httpStore->contentLength += length;
        
        if (length) return length + newline + 3- buf;
        else return 0;
    }
    else if(strncasecmp(buf,"\r\n",2)==0){
        return 0;
    }
    return -1;
}

void dumpStore(HttpStore* http_store){
    printf("+====Dumping Store======+\n"); 
    write(fileno(stdout), http_store->buf, http_store->length);
    fflush(stdout);
    printf("\n+====================+\n");
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
    S->content = malloc(STORE_SIZE);
    S->size = STORE_SIZE;
    S->contentSpace = STORE_SIZE;
    
    S->dynamicContent = 1;
    return S;
}

void freeHttpStore(HttpStore* S){
    if (S != (HttpStore*) 0){
        if (S->buf != (char*) 0)
            free(S->buf);
        if (S->dynamicContent && S->content != (char*) 0)
            free(S->content);
        free(S);
    }
}

void writeHttpHeaders(void *http, HttpHeader* first){
    HttpHeader* H;
    for(H=first; H != (HttpHeader*)0; H=H->next){
    //    switch(H->type){
    //        case -1://Http_A_ENCODING:
    //            sprintf(HTTP_BUF, "%s: deflate\r\n", H->header);    
    //        break;
    //        default:
                sprintf(HTTP_BUF, "%s: %s\r\n", H->header, H->data);
    //        break;
    //    }
        HttpWrite(http, HTTP_BUF, strlen(HTTP_BUF));
        printf("%s", HTTP_BUF);
    }

    // finish header with empty line
    HttpWrite(http, "\r\n", 2);
    write(fileno(stdout), "\r\n", 2);
}

void printHttpHeaders(HttpHeader **header){
    HttpHeader** tmp = header;
    printf("\n");
    while(*tmp != (HttpHeader*)0){
        printf("%s: %s\n", (*tmp)->header, (*tmp)->data);
        tmp = &((*tmp)->next);
    }
    printf("\n");
}
/*
void saveHttpHeaders(HttpStore* S){
    if (S->headerLength){
        char* tmp = S->headers;
        S->headers = malloc(S->headerLength);
        memmove(S->headers, tmp, S->headerLength);
    }
}*/

int HttpParseHeader(HttpHeader** header, char* httpbuf){
    static char headertype[100], data[10000];
    int ec;

    if (
            strncasecmp(httpbuf, "\r\n", 2) == 0 ||
            strncasecmp(httpbuf, "\r\n\r\n", 4) == 0 
       ){
        return 0;
    }

    ec = sscanf(httpbuf, "%100[^: ] %*[: ] %10000[^\r\n]",
            headertype, data);
    if (ec == 2){
        addHttpHeader(header, headertype, data);
        return (strlen(headertype) + strlen(data) + 4);
    }else{
            printf("--leftover str:%s\n", httpbuf);
            printf("--bytes: ");
            return -1;
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
        "Transfer-Encoding",
        "Content-Type",
        "Content-encoding"
    };
    static int headerTypes[] = {
        HTTPH_HOST,
        HTTPH_A_ENCODING,
        HTTPH_CL,
        HTTPH_T_ENCODING,
        HTTPH_CT,
        HTTPH_C_ENCODING
    };
    static int count =6;
    for(int i=0; i<count; i++){
        if (strncasecmp(
            headerStrs[i], str, strlen(headerStrs[i])
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

int deleteHttpHeader(HttpHeader** first, int type){
    if (*first == (HttpHeader*) 0)
        return -1;
    HttpHeader* tmp = *first;
    HttpHeader* prior = tmp;
    if (tmp->type == type){
        *first = (*first)->next;
        freeHttpHeader(&prior);
        return 0;
    }
    while(tmp != (HttpHeader*) 0){
        if (tmp->type == type){
           prior->next = tmp->next;
           freeHttpHeader(&tmp);
           return 0;
        }
        prior = tmp;
        tmp = tmp->next;
    }
    return -1;
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
        freeHttpHeader(last);
    }
}

void freeHttpHeader(HttpHeader** header){
    if (*header != (HttpHeader*) 0){
        if ((*header)->data != (char*) 0)
            free((*header)->data);
        if ((*header)->type == HTTPH_UNKNOWN && (*header)->header != (char*) 0)
            free((*header)->header);
        free(*header);
        *header = (HttpHeader*) 0;
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
    
    if (req->method != (char*) 0)
        free(req->method);
    if (req->url != (char*) 0)
        free(req->url);
    if (req->protocol != (char*) 0)
        free(req->protocol);
    if (req->SSL != (SSL_Connection*) 0)
        SSL_Close(req->SSL);
    if (req->is_ssl)
        req->path = (char*) 0;

    freeHttpStore(req->store);
    freeURL(req->host, req->path);
    freeHttpHeaders(&req->header);
}

void freeHttpResponse(HttpResponse* res){
    if (res->comment != (char*) 0)
        free(res->comment);
    if (res->protocol != (char*) 0)
        free(res->protocol);

    if (res->SSL != (SSL_Connection*) 0)
        SSL_Close(res->SSL);
    freeHttpStore(res->store);
    freeHttpHeaders(&res->header);
}


int parseHttpHeaders(HttpHeader** header, HttpStore* http_store){
    char* httpbuf = http_store->buf + http_store->offset;
    int l = 0;
    http_store->headerLength = 0; 
    // Parse all available headers.
    while((l = HttpParseHeader(header, httpbuf)) > 0){
        if (http_store->offset > http_store->length){
            printf("--EXCEEDING STORE SIZE %d\n", http_store->length);
            exit(0);
        }
        http_store->offset += l;
        http_store->headerLength += l;
        httpbuf +=l;
    }

    return l;
}

#define HTTP_CONTENT 1
#define HTTP_CHUNKED 2
#define HTTP_NO_CONTENT 3
int getHttpContent(HttpHeader* header, int* contentLength){
    HttpHeader* h = getHttpHeader(header, HTTPH_CL);
    if (h != (HttpHeader*) 0){
        *contentLength = atol(h->data);
        return (*contentLength ? HTTP_CONTENT : HTTP_NO_CONTENT);
    }else if((h = getHttpHeader(header, HTTPH_T_ENCODING)) != (HttpHeader*) 0){
        if (strncasecmp(h->data, "chunked", 7) == 0){
            return HTTP_CHUNKED;
        }
    }
    return HTTP_NO_CONTENT;
}
int parseHttpContent(HttpStore* http_store){
    int l;
    // trim offset if necessary
    while( (l = http_store->length - http_store->offset) < 0 )
        http_store->offset -= l;

    printf("reading content %d / %d\n",
            http_store->length - http_store->offset, 
            http_store->contentLength );
    // Check if the content length has been met.
    if (http_store->length - http_store->offset >= http_store->contentLength){
        saveHttpContent(http_store, http_store->buf + http_store->offset,
                http_store->contentLength);
        return 0;
    }else{
        return 1;
    }
}

int parseHttpChunks(HttpStore* http_store){
    char* httpbuf = http_store->buf+http_store->offset;
    int l;
    while( (l=readChunk(http_store, httpbuf)) > 0 ){
        http_store->offset += l;
        httpbuf += l;
        printf("got %d chunks\n",l);
    }
    return l;    
}

int HttpParse(void* http, HttpHeader** header, HttpStore *http_store){
    char* httpbuf = http_store->buf;
    if (http_store->state == E_connect){
        http_store->state = E_readHeader;
    }
    switch(http_store->state){
        // Read the first line of Http req/res for http/https
        case E_reReadMethod:
        case E_readMethod:
        case E_readStatus:
            if (http_store->state == E_readStatus)
                http_store->offset = 
                    HttpParseStatus((HttpResponse*)http, httpbuf);
            else
                http_store->offset = 
                    HttpParseMethod((HttpRequest*)http, httpbuf);
            
            //http_store->headers = httpbuf + http_store->offset;
            if (http_store->state == E_readMethod)
                return (http_store->state = E_connect);
            else
                return (http_store->state = E_readHeader);
        break;
        // Read in the headers
        case E_readMoreHeader:
        case E_readHeader:
            if ( parseHttpHeaders(header, http_store) == 0){
                http_store->headerLength += 2;  // Empty line
                http_store->offset += 2;        // Empty line
                switch(getHttpContent(*header, &http_store->contentLength)){
                    case HTTP_CONTENT: http_store->state = E_readContent;
                    break;
                    case HTTP_CHUNKED: http_store->state = E_readChunks;
                    break;
                    default: http_store->state = E_finished; break;
                }
                break;
            }else{
                // Not all the headers are present?
                printf("---Reading more of header\n");
                http_store->state = E_readMoreHeader;  
            }
        break;
        // Read in the content if its not chunked
        case E_continue:
        case E_readContent:
            
            if ( parseHttpContent(http_store) == 0)
                http_store->state = E_finished;
            else    // More data must be read in.
                http_store->state = E_continue;
        
        break;
        // Read in chunked content.
        case E_readMoreChunks: 
        case E_readChunks:
            if (parseHttpChunks(http_store) == 0)
                http_store->state = E_finished;
            else{   // More data must be read in
                http_store->state = E_readMoreChunks;
                printf("---need to read more chunks");
            }
        break;
    }
    return http_store->state;
}
