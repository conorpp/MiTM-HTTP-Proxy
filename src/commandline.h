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

static char* CL_ARGS[] = {
    "-p",
    "-r",
    "-after",
    "-before",
    "-replace",
    "-c",
    "-string",
    "-files",
    "-matchtag",
    "-matchattr",
    "--save-client-data",
    "--save-server-data",
    "-h",
    "-priv",
    "-cert",
    "-gravity",
    "-rickroll",
    "\0"
};

#define CL_VAL(x) ((x) < 32 ? (1<<(x)) : (x))
#define CL_PORT (1<<1)
#define CL_REGEX (1<<2)
#define CL_AFTER (1<<3)
#define CL_BEFORE (1<<4)
#define CL_REPLACE (1<<5)
#define CL_COUNT (1<<6)
#define CL_STRING (1<<7)
#define CL_FILES (1<<8)
#define CL_TAG (1<<9)
#define CL_ATTR (1<<10)
#define CL_SAVE_CLIENT (1<<11)
#define CL_SAVE_SERVER (1<<12)
#define CL_SAVE_HEADERS (1<<13)
#define CL_PRIV_FILE (1<<14)
#define CL_CERT_FILE (1<<15)
#define CL_GRAVITY (1<<16)
#define CL_RICKROLL (1<<17)
#define CL_NOTHING (99)

int parseArgs(int _argc, char* argv[], int* cur);

void Help();

void setProxSettings(int argc, char* argv[]);

#define MAX_FILES 500


#endif
