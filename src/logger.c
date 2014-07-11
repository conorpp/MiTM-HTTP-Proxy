#include "logger.h"

static int LOG_OPTS[] = {
    LOG_ALL,
    LOG_REQ_DATA,
    LOG_RES_DATA,
    LOG_REQ_HEADER,
    LOG_RES_HEADER,
    LOG_DEBUG,
    0
};

static int isLoggable(int f1, int logger){
    if (logger & LOG_ALL)
        return 1;
    for (int i = 0; LOG_OPTS[i]; i++)
        if ((LOG_OPTS[i] & f1) &&
                (LOG_OPTS[i] & logger))
            return 1;
    return 0;
}

void Log(int flags, char* msg, ...){
    if (GET_LOG_LEVEL(flags) > Logger.level)
        return;

    va_list args;
    va_start( args, msg );
    if (isLoggable(flags, Logger.logFlags))
        vprintf( msg, args );
    if (isLoggable(flags, Logger.outputFlags)&&
        Logger.output != (FILE*)0)
        vfprintf(Logger.output, msg, args);
    va_end( args );
}

void LogContent(int flags, char* msg, int length){
    char* tmp = malloc(length+1);
    memmove(tmp, msg, length);
    tmp[length] = '\0';
    Log(flags,"%s", tmp);
    if (tmp != (char*)0)
        free(tmp);

}
