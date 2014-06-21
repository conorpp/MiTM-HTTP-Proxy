#ifndef HTTP_H
#define HTTP_H

#include "utils.h"
#include "tcp.h"

/* HTTP/URL parsing
 * */


typedef struct _HTTPHeader{
    int type;           // HTTP header type
    char* header;
    char* data;         // HTTP header data
    int length;
    struct _HTTPHeader* next;   // pointer to next HTTP header
} HTTPHeader;

// Important information from a HTTP request.
typedef struct{
    char* method,       // HTTP method e.g. "GET", "CONNECT"
        * url,          // "<http[s]>://<hostname>[:port]/[path]"
        * protocol,      // HTTP proto e.g. "HTTP/1.1"
        * host,         // Target host
        * path;         // Target path
    int port,           // Target port
        ssl;            // HTTP/HTTPS
    HTTPHeader* header;
} HTTPRequest;

// Important information from a HTTP response.
typedef struct{
    char* protocol,       // HTTP method e.g. "GET", "CONNECT"
        * comment;          // "<http[s]>://<hostname>[:port]/[path]"
    int status;           // Target port
    HTTPHeader* header;
} HTTPResponse;


#define HTTP_CL 0
#define HTTP_HOST 1
#define HTTP_A_ENCODING 2
#define HTTP_UNKNOWN 3
void getHTTPHeaderType(HTTPHeader* head, char *str);

// add to linked list
void addHTTPHeader(HTTPHeader** first, char* type, char* data);

// get item from linked list
HTTPHeader* getHTTPHeader(HTTPHeader* first, int type);

// Free linked list
void freeHTTPHeaders(HTTPHeader** first);

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
int parseHTTPMethod(HTTPRequest* req, const char* str);

int parseHTTPStatus(HTTPResponse* req, const char* str);


// frees an HTTPRequest struct.
///@param req: pointer to struct to free.
void freeHTTPRequest(HTTPRequest* req);

void freeHTTPResponse(HTTPResponse* res);


#endif
