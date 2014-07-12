/* Command line interface for Prox
* */
#ifndef _COMMANDLINE_H_
#define _COMMANDLINE_H_

#include "utils.h"    // utils
#include "regex.h"    // Regexes
#include "tcp.h"      // Check hostname
#include "proxy.h"    // settings struct

#define CL_VAL(x) (CL_ARGS[(x)].val)
#define CL_NOTHING (99)

// Pair string representation with a unique number
struct _Arg_{
    char* str;
    int val;
};

// The arguments
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
#define CL_APPEND (1<<6)
    {"-append", CL_APPEND},
#define CL_PREPEND (7)
    {"-prepend", CL_PREPEND},
#define CL_COUNT (3)
    {"-c", CL_COUNT},
#define CL_STRING (1<<7)
    {"-string", CL_STRING},
#define CL_FILES (1<<8)
    {"-files", CL_FILES},
#define CL_TAG (1<<9)
    {"-matchtag", CL_TAG},
#define CL_ATTR (1<<10)
    {"-matchattr", CL_ATTR},
#define CL_HOST (19)
    {"-host", CL_HOST},
#define CL_ADD_HEADERS (1 << 18)
    {"--add-headers", CL_ADD_HEADERS},
#define CL_BLOCK_HEADERS (1 << 19)
    {"--block-headers", CL_BLOCK_HEADERS},
#define CL_REPLACE_HEADERS (1 << 20)
    {"--replace-headers", CL_REPLACE_HEADERS},
#define CL_SAVE_CLIENT (1<<11)
    {"--save-client-data", CL_SAVE_CLIENT},
#define CL_SAVE_SERVER (1<<12)
    {"--save-server-data", CL_SAVE_SERVER},
#define CL_SAVE_HEADERS (1<<13)
    {"-headers", CL_SAVE_HEADERS},
#define CL_PRIV_FILE (1<<14)
    {"-pk", CL_PRIV_FILE},
#define CL_CERT_FILE (1<<15)
    {"-ca", CL_CERT_FILE},
#define CL_TIMEOUT (5)
    {"-timeout", CL_TIMEOUT},
#define CL_GRAVITY (1<<16)
    {"-gravity", CL_GRAVITY},
#define CL_RICKROLL (1<<17)
    {"-rickroll", CL_RICKROLL},
    {"\0",0}
};

// uses static variables to 1 arg per function call.
///@return: the argument type or -1 when finished.
///@param _argc: the number of arguments in argv.
///@param argv: the arguments.
///@param cur: this fills in with parseArgs's current index in argv.
int parseArgs(int _argc, char* argv[], int* cur);

// Print out the help text.
void Help();

// State machine that uses parseArgs to set Prox's settings.
void setProxSettings(int argc, char* argv[]);

// You can't specify more than 500 files to insert.
#define MAX_FILES 500


#endif
