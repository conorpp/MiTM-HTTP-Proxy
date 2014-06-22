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
        * protocol,     // HTTP proto e.g. "HTTP/1.1"
        * host,         // Target host
        * path;         // Target path
    int port,           // Target port
        ssl;            // HTTP/HTTPS
    HTTPHeader* header;
} HTTPRequest;

// Important information from a HTTP response.
typedef struct{
    char* protocol,       // HTTP method e.g. "GET", "CONNECT"
        * comment;        // "<http[s]>://<hostname>[:port]/[path]"
    int status;           // Target port
    HTTPHeader* header;
} HTTPResponse;

// Stateful header for processing saved HTTP req/res data
typedef struct{
    char* buf;          // Stored data
    int length;         // length of stored data
    int offset;         // length of data that's been processed
    int state;          // the state of the transaction
    char* headers;      // pointer to start of headers in data
    char* content;      // pointer to start of content in data
    int contentLength;  // how long content is
    int headerLength;   // how long headers is
}HTTPStore;

// Possible states for an HTTPStore 
enum HttpState{ 
    E_readMethod=0,     // reading first line of HTTP request.
    E_readStatus,       // reading first line HTTP response.
    E_connect,          // connecting to host.
    E_readHeader,       // reading the header.
    E_readContent,      // reading the content.
    E_finished          // all data has been processed.
};

// Store data from an HTTP transaction.
// Statically allocated so it may only be
// used for one transaction per process at
// a time.
///@param data: the data to be store. Pass in NULL
///             to reset the store and use flags.
///@param length: how much of the data to store.
///@param flags: pass in one of the macros below.
///              Only when store is reset.
#define STORE_SIZE 1000000      // data cap for HTTP transaction
#define HTTP_REQ (1 << 0)       // HTTP transaction is a request
#define HTTP_RES (1 << 1)       // HTTP transaction is a response
#define IS_REQ(x) (x&1) 
#define IS_RES(x) (x&2)
HTTPStore* store(char* data, int length, int flags);

// Print out the headers to stdout of a header 
// linked list for debugging.
///@param header: the first header in linked list.
void printHTTPHeaders(HTTPHeader **header);


// Parses a string and adds a header to a header
// linked list
///@param header: the first header in linked list.
///@param httpbuf: the string to be parsed.
int parseHTTPHeader(HTTPHeader** header, char* httpbuf);


// Adds a numeric value and respective string
// for a HTTP header to a HTTPHeader struct,
// Depending on the headertype of the string.
///@param head: the HTTPHeader struct to add data to
///@param str: the string to parse.
#define HTTPH_CL 0              // Content-length
#define HTTPH_HOST 1            // Host
#define HTTPH_A_ENCODING 2      // Accept-encoding
#define HTTPH_UNKNOWN 3         // Other
void getHTTPHeaderType(HTTPHeader* head, char *str);

// Adds a HTTP header for string representations of a header
void addHTTPHeader(HTTPHeader** first, char* type, char* data);

// get item from linked list
HTTPHeader* getHTTPHeader(HTTPHeader* first, int type);

// Free a HTTP linked list structure
///@param first: first item in header linked list
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

// parses the first line of an HTTP request and adds
// information to HTTPRequest structure
///@param str: the HTTP request string.
///@param req: pointer to HTTPRequest struct to allocate.
int parseHTTPMethod(HTTPRequest* req, const char* str);

// Same as parseHTTPMethod but for HTTP response.
int parseHTTPStatus(HTTPResponse* req, const char* str);


// frees an HTTPRequest struct.
///@param req: pointer to struct to free.
void freeHTTPRequest(HTTPRequest* req);

// frees an HTTPResponse struct
///@param res: pointer to struct to free.
void freeHTTPResponse(HTTPResponse* res);


#endif
