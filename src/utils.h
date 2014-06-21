#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>      // printf, fflush, stderr, stdout
#include <stdlib.h>     // exit
#include <errno.h>      // errno, perror
#include <sys/wait.h>   // waitpid, WHOHANG
#include <signal.h>     // signal

/*Error Checking, signal catching
 ****************************************************/

// exit with a message along with errno message if 
// it's set
void die(const char *msg);

// Handler to reap zombie processes
void sigchld_handler(int s);


#endif


