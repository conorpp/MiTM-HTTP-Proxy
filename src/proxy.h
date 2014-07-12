/* Functionaly specific to application and proxying
* */

#ifndef _PROXY_H_
#define _PROXY_H_

#include <stdlib.h>  // malloc/free
#include <string.h>  // mem*
#include <zlib.h>    // Gzip encoding/decoding
#include "utils.h"   // utils
#include "regex.h"   // Regex type
#include "http.h"   // Regex type
#include "commandline.h"  // commandline args/settings specific to application

#define PROX_REPLACE      (1 << 20)
#define PROX_BLOCK        (1 << 19)
#define PROX_INSERT       (1 << 18)
typedef struct{
    HttpHeader* headers;
    int flags;
} HeaderTarget;

struct __SETTINGS__{
    struct{
        int position;
        int offset;
        uchar findTag;
        uchar findAttr;
        uchar saveClient;
        uchar saveServer;
        uchar saveHeaders;
        long long int count;
        int timeout;
        char* host;
    }options;
    struct{
        uchar enabled;
        char* certfile;
        char* privfile;
    }ssl;
    char* targetHost;
    char* regexString;
    Regex* regex;
    char* replaceString;
    char** files;
    int filenum;
    char* port;
    int(*match)(const char*, Range*, Regex*);

    HeaderTarget* targetHeaders;
    int thNum;
}Prox;

void freeHeaderTarget(HeaderTarget* ht);

// Decodes a deflate or gzip buffer.
///@param gzip: the compressed buffer
///@param length: the length of gzip in bytes
void decodeGzip(char** gzip, int *length);

void proxyHeaders(HttpHeader** first);

int isTargetServerHost(HttpHeader* first);

void addTargetHeader(char* type, char* data, int flags);

void printTargetHeaders();




#endif
