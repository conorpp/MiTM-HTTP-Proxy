/* Functionaly specific to application and proxying
* */

#ifndef _PROXY_H_
#define _PROXY_H_

#include <stdlib.h>  // malloc/free
#include <string.h>  // mem*
#include <zlib.h>    // Gzip encoding/decoding
#include "utils.h"   // utils
#include "regex.h"   // Regex type
#include "commandline.h"  // commandline args/settings specific to application


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
}Prox;



// Decodes a deflate or gzip buffer.
///@param gzip: the compressed buffer
///@param length: the length of gzip in bytes
void decodeGzip(char** gzip, int *length);




#endif
