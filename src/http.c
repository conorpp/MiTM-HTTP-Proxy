#include "http.h"

void parseHTTPRequest(const char* str, struct HTTPRequest* req){
    if (sizeof str > HTTP_BUF_SIZE){
        printf("HTTP request str is longer than %d bytes", HTTP_BUF_SIZE);
        exit(3);
    }
    int size, offset;
    
    // method
    if (sscanf(str, "%s", HTTP_BUF) != 1)
        die("invalid request string for method");
    req->method = (char *)malloc( (size = offset = strlen(HTTP_BUF)+1) );
    memmove(req->method, HTTP_BUF, size);
    // url
    
    if (sscanf(&str[offset], "%s", HTTP_BUF) != 1)
        die("invalid request string for url");
    req->url = (char *) malloc( (size = strlen(HTTP_BUF)+1) );
    memmove(req->url, HTTP_BUF, size);
    offset += (size);
    //printf("parsed url: %s\n", req->url);
    
    // protocol
    if (sscanf(&str[offset], "%s", HTTP_BUF) != 1)
        die("invalid request string for protocol");
    req->protocol = (char *) malloc( (size = strlen(HTTP_BUF)+1) );
    memmove(req->protocol, HTTP_BUF, size);
    parseURL(req->url, &req->host, &req->path, &req->port, &req->ssl);
    if (strncasecmp(req->method, "CONNECT", 7) == 0) req->ssl = 1;
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

void freeHTTPRequest(struct HTTPRequest* req){

    if (req->method != (char*) 0)
        free(req->method);
    if (req->url != (char*) 0)
        free(req->url);
    if (req->protocol != (char*) 0)
        free(req->protocol);
    freeURL(req->host, req->path);
}



