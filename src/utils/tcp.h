/* TCP connections and networking
* */

#ifndef TCP_H
#define TCP_H

#include <string.h>         //memset, memmove, str functions
#include <netdb.h>          // addrinfo misc
#include <unistd.h>         // read, write, close, fork
#include <netinet/in.h>     // ntohl, etc.
#include <arpa/inet.h>      // inet_aton
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

/// @return 0 if the host is visible.
/// Returns a gai_error otherwise.
int hostIsAlive(char* host);

// Get the integer representation of 
// a IP address in . notation
///@return the integer IP
///@param ip: the . notation ip address
unsigned int getIpInt(char* ip);

#endif
