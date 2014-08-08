#ifndef _RAW_H_
#define _RAW_H_

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

// Structure for a raw IP level socket
typedef struct _IPSocket{
    int sockfd;
    int proto;
    struct sockaddr_in addr;
    int addr_size;
}IPSocket;

// Structure for a IP socket node in a linked list
typedef struct _IPSocketNode{
    struct _IPSocketNode* next;
    IPSocket* ipsock;
    int i;
    int data_ready;
    int data_misses;
} IPSocketNode;

// Linked list header for IP raw sockets
typedef struct _IPSocketList{
    IPSocketNode* list;
    int length;
    int maxfd;
    fd_set fdset;
} IPSocketList;

// Do select poll on raw socket list
// and mark the FD_SET ones as data_ready
void SelectIPSocket(IPSocketList* list);

// Get a new raw socket linked list structure
IPSocketList* getIPSocketList();

// Free an entire raw socket linked list
void freeIPSocketList(IPSocketList** list);

// Add a raw socket to a linked list
void addIPSocket(IPSocketList* list, IPSocket* ipsock);

// Remove a node from a linked list.  Matches the index.
void removeIPSocket(IPSocketList* listheader, IPSocketNode** node);

// Bind a file descriptor to a nbo address and port.
void Bind_str(int fd, char* addr, uint16_t port);

// Bind a file descriptor to a address and port.
void Bind(int fd, uint32_t addr, uint16_t port);

// Get a new IP raw socket that uses given addr/port/proto
// to send to and receive from.  pass in RAW_BIND flag
// to bind to the given address as well.
#define RAW_BIND (1 << 0)
IPSocket* getRawSocket(uint32_t addr, uint16_t port, uint8_t proto, int flags);

// use string instead of nbo ip addr
IPSocket* getRawSocket_str(char* addr, uint16_t port, uint8_t proto, int flags);

// Free a raw socket.
void freeRawSocket(IPSocket* ipsock);

// Recieve data from a raw socket.  Blocks
int Recvfrom(IPSocket* ipsock, char* buf, int lim);

// Send data into a raw socket.
int Sendto(IPSocket* ipsock, char* buf, int lim);

#endif
