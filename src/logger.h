/* Application uses Log for output so verbosity/output type/filenames
*  can be easily configured.
* */

#ifndef _LOGGER_H_
#define _LOGGER_H_

#include <stdarg.h>    // variable arguments
#include <stdio.h>     // FILE*
#include <stdlib.h>    // malloc/free
#include <string.h>    // mem*

// Settings used for Log
struct __LOGSETTINGS__{
    int level;
    int logFlags;
    int outputFlags;
    FILE* output;
    int outputfd;
}Logger;

// Logs output to stdout and/or a file
// depending on the parameters in struct Logger.
// as well as the flags pass in.
///@param flags: pass in conditonals of the log to compare to Logger
///@param msg: format string for printf, fprintf
///@param ...: variable number of arguments for format string.
void Log(int flags, char* msg, ...);

// Applies a buffer to Log.
///@param flags: pass in conditonals of the log to compare to Logger
///@param msg: buffer to write
///@param length: number of bytes to write.
void LogContent(int flags, const char* msg, int length);

// Initialize Logger with default settings.
void initLogger();

// Parameters / flags

#define GET_LOG_LEVEL(x) ((x) & 0x1f)
#define LOG1 (1<<0)
#define LOG2 (1<<1)
#define LOG3 (1<<2)
#define LOG4 (1<<3)
#define LOG5 (1<<4)
#define LOG_DISABLED (1<<5)

#define LOG_ALL (1<<6)

#define LOG_REQ_DATA (1<<7)
#define LOG_RES_DATA (1<<8)
#define LOG_REQ_HEADER (1<<9)
#define LOG_RES_HEADER (1<<10)
#define LOG_DEBUG (1<<11)
#define LOG_INFO (1<<12)

// Used by Log
static int LOG_OPTS[] = {
    LOG_ALL,
    LOG_REQ_DATA,
    LOG_RES_DATA,
    LOG_REQ_HEADER,
    LOG_RES_HEADER,
    LOG_DEBUG,
    LOG_INFO,
    0
};


#endif
