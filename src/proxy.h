#ifndef _PROXY_H_
#define _PROXY_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include "utils.h"
#include "regex.h"



/* Functionaly specific to application and proxying
* */

struct __SETTINGS__{
    struct{
        uchar gravity;
        uchar rickroll;
    }events;
    struct{
        int position;
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
}Prox;



// Decodes a deflate or gzip buffer.
///@param gzip: the compressed buffer
///@param length: the length of gzip in bytes
void decodeGzip(char** gzip, int *length);




#endif
