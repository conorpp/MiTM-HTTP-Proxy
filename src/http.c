#include "http.h"


HTTPStore* store(char* data, int length, int flags){
    static char buffer[STORE_SIZE];
    static HTTPStore S;
    if (data != (char*)0){
        if (S.length + length > STORE_SIZE)
            die("store:  memory exceeded.");
        memmove(&buffer[S.length], data, length);
        S.length += length;
    }else{
        S.buf = buffer;
        S.length = 0;
        S.offset = 0;
        if (IS_REQ(flags))
            S.state = E_readMethod;
        else 
            S.state = E_readStatus;
        S.contentLength = 0;
        S.headerLength = 0;
        S.headers = buffer;
        S.content = buffer;
    }
    return &S;
}

void printHTTPHeaders(HTTPHeader **header){
    HTTPHeader** tmp = header;
    printf("\n");
    while(*tmp != (HTTPHeader*)0){
        printf("%s: %s\n", (*tmp)->header, (*tmp)->data);
        tmp = &((*tmp)->next);
    }
    printf("\n");
}



int parseHTTPHeader(HTTPHeader** header, char* httpbuf){
    static char headertype[100], data[1000];
    int ec;
    ec = sscanf(httpbuf, "%100[^:] %*[: ] %1000[^\r\n]",
            headertype, data);

    if (ec == 2){
        addHTTPHeader(header, headertype, data);
        return (strlen(headertype) + strlen(data) + 4);
    }else
        if (
                strncasecmp(httpbuf, "\n\n", 2) == 0 ||
                strncasecmp(httpbuf, "\r\n\r\n", 4) 
           ){
            return 0;
    }

    return -1;
}

void getHTTPHeaderType(HTTPHeader* head, char *str){
    static char* headerStrs[] = {
        "Host",
        "Accept-Encoding",
        "Content-length"
    };
    static int headerTypes[] = {
        HTTPH_HOST,
        HTTPH_A_ENCODING,
        HTTPH_CL
    };
    static int count = 3;
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

void addHTTPHeader(HTTPHeader** first, char* type, char* data){
    HTTPHeader** tmp = first;
    if (*tmp != (HTTPHeader*)0){
      while((*tmp)->next != (HTTPHeader*) 0){
        tmp = &((*tmp)->next);
      }
      (*tmp)->next = malloc(sizeof(HTTPHeader));
      tmp = &((*tmp)->next);
    }
    else{
        *tmp = malloc(sizeof(HTTPHeader));
    }
    getHTTPHeaderType(*tmp, type);
    (*tmp)->length = strlen(data)+1;
    (*tmp)->data = malloc( (*tmp)->length);
    (*tmp)->next = (HTTPHeader*)0;
    memmove((*tmp)->data, data, (*tmp)->length);
}

HTTPHeader* getHTTPHeader(HTTPHeader* first, int type){
    HTTPHeader* tmp = first;
    while(tmp != (HTTPHeader*) 0){
        if (tmp->type == type)
            return tmp;
        tmp = tmp->next;
    }
    return (HTTPHeader*) 0;
}

void freeHTTPHeaders(HTTPHeader** first){
    HTTPHeader **tmp, **last;
    tmp = first;
    while(*tmp != (HTTPHeader*)0){
        last = tmp;
        tmp = &((*tmp)->next);
        if ((*last)->data != (char*) 0)
            free((*last)->data);
        if ((*last)->type == HTTPH_UNKNOWN && (*last)->header != (char*) 0)
            free((*last)->header);
        free(*last);
        *last = (HTTPHeader*) 0;
    }
}

int parseHTTPMethod(HTTPRequest* req, const char* str){
    if (sizeof str > HTTP_BUF_SIZE){
        printf("HTTP request str is longer than max %d bytes", HTTP_BUF_SIZE);
        exit(3);
    }
    static char *method = &HTTP_BUF[0];
    static char *url = &HTTP_BUF[101];
    static char *protocol = &HTTP_BUF[1602];
    int size, total = 0;

    if(sscanf(str, "%100s %1500s %100s", method, url, protocol)!=3)
        die("invalid HTTP request");
    req->method = (char *) malloc( (size = strlen(method)+1) );
    memmove(req->method, method, size);
    total += size;

    req->url = (char *) malloc( (size = strlen(url)+1) );
    memmove(req->url, url, size);
    total += size;

    req->protocol = (char *) malloc( (size = strlen(protocol)+1) );
    memmove(req->protocol, protocol, size);
    total += size;

    parseURL(req->url, &req->host, &req->path, &req->port, &req->ssl);

    if (strncasecmp(req->method, "CONNECT", 7) == 0) req->ssl = 1;
    return total + 1; // two spaces, \r, \n
}



int parseHTTPStatus(HTTPResponse* res, const char* str){
    if (sizeof str > HTTP_BUF_SIZE){
        printf("HTTP request str is longer than max %d bytes", HTTP_BUF_SIZE);
        exit(3);
    }
    static char *protocol = &HTTP_BUF[0];
    static char *comment = &HTTP_BUF[101];

    int size, total = 0;

    if(sscanf(str, "%100s %d %1000[^\r\n]", protocol, &res->status, comment)!=3)
        die("invalid HTTP response");

    res->comment = (char *) malloc( (size = strlen(comment)+1) );
    memmove(res->comment, comment, size);
    total += size;

    res->protocol = (char *) malloc( (size = strlen(protocol)+1) );
    memmove(res->protocol, protocol, size);
    total += size;

    return total + 1; // two spaces, \r, \n
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
    if (sscanf(&url[offset], "%[^/:]", HTTP_BUF) != 1)
        die("invalid url");

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

void freeHTTPRequest(HTTPRequest* req){

    if (req->method != (char*) 0)
        free(req->method);
    if (req->url != (char*) 0)
        free(req->url);
    if (req->protocol != (char*) 0)
        free(req->protocol);
    freeURL(req->host, req->path);
    freeHTTPHeaders(&req->header);
}

void freeHTTPResponse(HTTPResponse* res){
    if (res->comment != (char*) 0)
        free(res->comment);
    if (res->protocol != (char*) 0)
        free(res->protocol);
    freeHTTPHeaders(&res->header);
}




