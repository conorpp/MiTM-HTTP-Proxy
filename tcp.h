#ifndef TCP_H
#define TCP_H

/*
*   Functionality for TCP connections
*/

#include <stdio.h>
#include <string.h>         //memset, memmove, str functions
#include <netdb.h>          // addrinfo misc
#include <unistd.h>         // read, write, close, fork

#include "utils.h"

// looks up a host and fills addrinfo res 
// with tcp addr/port/protocol/family options
// Be sure to free res when finished.
struct addrinfo* getTCPInfo(char *hostname, char* port);

// Binds to an address and port
// to liston on for TCP connections
// Binds to localhost if addr is NULL
int Listen(void *addr, char *port);

// Establishes a TCP connection with 
// a host on a particular port and 
// returns the file descriptor
int Connect(char *hostname, int port);


#endif
