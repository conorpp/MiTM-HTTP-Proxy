#include "logger.h"


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
    int log_file = (isLoggable(flags, Logger.outputFlags)&&
                    Logger.output != (FILE*)0) ? 1 : 0;
    va_list args;
    va_list args2;
    int copied = 0;
    va_start( args, msg );
    if (GET_LOG_LEVEL(flags) <= Logger.level)
        if (isLoggable(flags, Logger.logFlags)){
            if (log_file){
              va_copy(args2, args);
              copied = 1;
            }
            vprintf( msg, args );
        }
    if (log_file && isLoggable(flags, Logger.outputFlags)){
        if (!copied)
          va_copy(args2, args);
        vfprintf(Logger.output, msg, args2);
        fflush(Logger.output);
    }
    va_end( args );
}

void LogContent(int flags, const char* msg, int length){
    if (length < 0){
        printf("Length must be positive to log content\n");
        exit(2);
    }
    char* tmp = malloc(length+1);
    memmove(tmp, msg, length);
    tmp[length] = '\0';
    Log(flags,"%s", tmp);
    if (tmp != (char*)0)
        free(tmp);
}

void initLogger(){
  memset(&Logger, 0, sizeof(struct __LOGSETTINGS__));
  Logger.level = LOG2;
  Logger.logFlags |= LOG_ALL;
}
