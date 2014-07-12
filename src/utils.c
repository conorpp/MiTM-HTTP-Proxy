#include "utils.h"

void die(const char *msg, ...){
    char diebuf[10000];
    va_list args;
    vprintf( msg, args );
    vsprintf(diebuf, msg, args);
    va_end( args );

    if (!errno) fprintf(stderr, "%s\n", diebuf);
    else perror(diebuf);

    fflush(stderr);
    fflush(stdout);
    exit(2);
}

void sigchldHandler(int sig){
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

void timeoutHandler(int sig){
  die("Timed out.  Exiting process");
}
