/* Command line interface for Prox
* */
#ifndef _COMMANDLINE_H_
#define _COMMANDLINE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "regex.h"
#include "tcp.h"
#include "proxy.h"

#define CL_VAL(x) (CL_ARGS[(x)].val)
#define CL_NOTHING (99)

struct _Arg_{
    char* str;
    int val;
};

static struct _Arg_ CL_ARGS[] = {
#define CL_PORT (1<<1)
    {"-p",CL_PORT},
#define CL_REGEX (1<<2)
    {"-r", CL_REGEX},
#define CL_AFTER (1<<3)
    {"-after", CL_AFTER},
#define CL_BEFORE (1<<4)
    {"-before", CL_BEFORE},
#define CL_REPLACE (1<<5)
    {"-replace", CL_REPLACE},
#define CL_COUNT (1<<6)
    {"-c", CL_COUNT},
#define CL_STRING (1<<7)
    {"-string", CL_STRING},
#define CL_FILES (1<<8)
    {"-files", CL_FILES},
#define CL_TAG (1<<9)
    {"-matchtag", CL_TAG},
#define CL_ATTR (1<<10)
    {"-matchattr", CL_ATTR},
#define CL_SAVE_CLIENT (1<<11)
    {"--save-client-data", CL_SAVE_CLIENT},
#define CL_SAVE_SERVER (1<<12)
    {"--save-server-data", CL_SAVE_SERVER},
#define CL_SAVE_HEADERS (1<<13)
    {"-h", CL_SAVE_HEADERS},
#define CL_PRIV_FILE (1<<14)
    {"-pk", CL_PRIV_FILE},
#define CL_CERT_FILE (1<<15)
    {"-ca", CL_CERT_FILE},
#define CL_GRAVITY (1<<16)
    {"-gravity", CL_GRAVITY},
#define CL_RICKROLL (1<<17)
    {"-rickroll", CL_RICKROLL},
    {"\0",0}
};

int parseArgs(int _argc, char* argv[], int* cur);

void Help();

void setProxSettings(int argc, char* argv[]);

#define MAX_FILES 500


#endif
