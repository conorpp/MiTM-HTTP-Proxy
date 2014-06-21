#ifndef HTTP_H
#define HTTP_H

#include "utils.h"
#include "tcp.h"

/* HTTP/URL parsing
 * */

// Important information from a HTTP request.
struct HTTPRequest{
    char* method,       // HTTP method e.g. "GET", "CONNECT"
        * url,          // "<http[s]>://<hostname>[:port]/[path]"
        * protocol,      // HTTP proto e.g. "HTTP/1.1"
        * host,         // Target host
        * path;         // Target path
    int port,           // Target port
        ssl;            // HTTP/HTTPS
};

// Buffer to reuse for reading/writing
#define HTTP_BUF_SIZE 10000
static char HTTP_BUF[HTTP_BUF_SIZE];

// Parses a given url and fills in the host and path pointers.
// Sets the respective port and indicates if it's SSL or not.
///@param url: the url string to parse.
///@param host: pointer to string to allocate for host name in url.
///@param path: pointer to string to allocate for path in url.
///@param port: pointer to int to set from url.
///@param ssl: pointer to int that will be set to 1 if https.
void parseURL(const char* url, char** host, char** path, int* port, int *ssl);

// Frees the host and path components allocated by parseURL
///@param host: host string allocated
///@param path: path string allocated
void freeURL(char* host, char* path);

// parses the first line of an HTTP request and creates
// a HTTPRequest struct.
///@param str: the HTTP request string.
///@param req: pointer to HTTPRequest struct to allocate.
void parseHTTPRequest(const char* str, struct HTTPRequest* req);


// frees an HTTPRequest struct.
///@param req: pointer to struct to free.
void freeHTTPRequest(struct HTTPRequest* req);


#endif
