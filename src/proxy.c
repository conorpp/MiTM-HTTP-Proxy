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
