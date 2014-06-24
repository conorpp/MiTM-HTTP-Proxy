#ifndef SSL_UTILS_H
#define SSL_UTILS_H

#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "utils.h"

typedef struct{
    SSL_CTX* handle;
    SSL* socket;
} SSL_Connection;


SSL_CTX* SSL_SERVER_HANDLE;

// Wraps a http structure with ssl
#define SSL_ACCEPT (1 << 0)
#define SSL_CONNECT (1 << 1)
#define IS_SSL_ACCEPT(x) ((x)&1)
#define IS_SSL_CONNECT(x) ((x)&2)
void SSLWrap(void *http, int flags);

//Load libraries for SSL and init globals.
///@param certFile: the RSA signed CA file.
///@param privKeyFile: the private key for CA file.
void SSL_Init(char *certFile, char* privKeyFile);
    
//Takes a already connected TCP file descriptor
//and wraps it in SSL.  For starting SSL
//handshake with server.
///@param sockfd the file descriptor
SSL_Connection* SSL_Connect(int sockfd);

//Takes a connected file descriptor 
//and wraps it in SSL.  For listening
//for a SSL handshake from a client.
SSL_Connection* SSL_Accept(int sockfd);

//Free a SSL_Connection structure
void SSL_Close(SSL_Connection* sslcon);



#endif










