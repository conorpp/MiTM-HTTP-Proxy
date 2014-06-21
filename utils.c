#include "utils.h"

void die(const char *msg){
    if (!errno) printf("%s\n", msg);
    else perror(msg);
    fflush(stderr);
    fflush(stdout);
    exit(2);
}

void sigchld_handler(int s){
    while(waitpid(-1, NULL, WNOHANG) > 0);
}



