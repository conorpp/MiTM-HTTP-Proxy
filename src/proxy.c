#include "proxy.h"


void decodeGzip(char** gzip, int *length){
    uLong ucL = 32768;
    Bytef*buf = malloc(ucL);
    uLong cL = *length;
    int ec;
    z_stream strm;
    memset(&strm, 0, sizeof(z_stream));
    strm.next_in = (Bytef *) *gzip;
    strm.avail_in = cL;

    if (inflateInit2(&strm, (16+MAX_WBITS)) != Z_OK) {
        die("inflateInit2 failed");
    }
    do{
        if (strm.total_out >= ucL ) {
            buf = realloc(buf, (ucL *= 2));
            Log(LOG_DEBUG|LOG2,"Made more space for decompression %d\n", (int)ucL);
        }
        strm.next_out = buf + strm.total_out;
        strm.avail_out = ucL - strm.total_out;

    }while((ec=inflate(&strm, Z_SYNC_FLUSH)) == Z_OK);

    switch(ec){
        case Z_OK: break;
        case Z_BUF_ERROR: die("Z_BUF_ERROR"); break;
        case Z_MEM_ERROR: die("Z_MEM_ERROR"); break;
        case Z_DATA_ERROR: die("Z_DATA_ERROR"); break;
    }

    char *tmp = *gzip;
    *gzip = (char*)buf;
    if (tmp != (char*) 0)
        free(tmp);
    *length = (int)strm.total_out;
}

HeaderTarget* getHeaderTarget(char *headerType, char* headerData, int flags){
    HeaderTarget* ht = malloc(sizeof(HeaderTarget));
    ht->flags = flags;
    addHttpHeader(&ht->headers, headerType, headerData);
    return ht;
}
void freeHeaderTarget(HeaderTarget* ht){
    if (ht != (HeaderTarget*) 0){
        freeHttpHeaders(&ht->headers);
        free(ht);
    }
}

void proxyHeaders(HttpHeader** first){
    if (Prox.targetHeaders == (HeaderTarget*)0)
        return;
    for (int i=0; i<Prox.thNum; i++){
        // remove blocked headers
        if (Prox.targetHeaders[i].flags & PROX_BLOCK)
            deleteHttpHeader(first, Prox.targetHeaders[i].headers->header, 0);
        // add inserted headers
        else if (Prox.targetHeaders[i].flags & PROX_INSERT)
            addHttpHeader(first, Prox.targetHeaders[i].headers->header,
                                 Prox.targetHeaders[i].headers->data);
        // replace existing headers
        else if (Prox.targetHeaders[i].flags & PROX_REPLACE) {
            if ( deleteHttpHeader(first,
                    Prox.targetHeaders[i].headers->header, 0) == 0 )
                addHttpHeader(first, Prox.targetHeaders[i].headers->header,
                                     Prox.targetHeaders[i].headers->data);
        }
    }

}

int isTargetServerHost(HttpHeader* first){
    printf("--target host is %s\n", Prox.options.host);
    if (Prox.options.host == (char*) 0)
        return 1;
    HttpHeader* h = getHttpHeader(first, HTTPH_HOST);
    if (h != (HttpHeader*) 0){
        printf("--checcking %s\n", h->data);
        if (strstr(h->data, Prox.options.host) != (char*)0){
            printf("-- its a match!\n");
            return 1;
        }
    }
    printf("-- its NOT a match!\n");
    return 0;
}

void addTargetHeader(char* type, char* data, int flags){
    if (!Prox.thNum++){
        Prox.targetHeaders = malloc(sizeof(HeaderTarget));
    }else{
        Prox.targetHeaders = realloc(Prox.targetHeaders,
                                    sizeof(HeaderTarget) * (Prox.thNum));
    }
    addHttpHeader(&Prox.targetHeaders[Prox.thNum-1].headers, type,data);
    Prox.targetHeaders[Prox.thNum-1].flags = flags;
}

void printTargetHeaders(){
    for (int i=0; i<Prox.thNum; i++){
        switch(Prox.targetHeaders[i].flags){
            case PROX_BLOCK:
            printf("Blocking \"%s\"\n",
                 Prox.targetHeaders[i].headers->header);
            break;
            case PROX_REPLACE:
            printf("Replacing \"%s:%s\"\n",
                 Prox.targetHeaders[i].headers->header, Prox.targetHeaders[i].headers->data);
            break;
            case PROX_INSERT:
            printf("Adding \"%s:%s\"\n",
                 Prox.targetHeaders[i].headers->header, Prox.targetHeaders[i].headers->data);
            break;
        }

    }
}
