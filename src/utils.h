#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>      // printf, fflush, stderr, stdout
#include <stdlib.h>     // exit
#include <errno.h>      // errno, perror
#include <sys/wait.h>   // waitpid, WHOHANG
#include <signal.h>     // signal
#include <stdint.h>

/*Error Checking, signal catching, types
 ****************************************************/


#if UINTPTR_MAX == 0xffffffff
    typedef long PTR_SIZE;      // 32 bit
#elif UINTPTR_MAX == 0xffffffffffffffff
    typedef long long PTR_SIZE; // 64 bit
#else
    typedef short PTR_SIZE;     // 16bit?
#endif


// exit with a message along with errno message if 
// it's set
void die(const char *msg);

// Handler to reap zombie processes
void sigchld_handler(int s);


#endif


