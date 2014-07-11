#ifndef _LOGGER_H_
#define _LOGGER_H_

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct __LOGSETTINGS__{
    int level;
    int logFlags;
    int outputFlags;
    FILE* output;
}Logger;


void Log(int flags, char* msg, ...);
void LogContent(int flags, char* msg, int length);

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

#endif
