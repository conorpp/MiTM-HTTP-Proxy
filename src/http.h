#ifndef HTTP_H
#define HTTP_H

#include "utils.h"
#include "tcp.h"
#include "ssl.h"

/* Http library
 * */


typedef struct _HttpHeader{
    int type;           // Http header type
    char* header;
    char* data;         // Http header data
    int length;
    struct _HttpHeader* next;   // pointer to next Http header
} HttpHeader;

// Stateful header for processing saved Http req/res data
typedef struct{
    char* buf;          // Stored data
    int size;           // Storage capacity
    int length;         // length of stored data
    int offset;         // length of data that's been processed
    int state;          // the state of the transaction
    char* headers;      // pointer to start of headers in data
    char* content;      // pointer to start of content in data
    int contentLength;  // how long content is
    int headerLength;   // how long headers is
}HttpStore;

// Important information from a Http request.
typedef struct{
    char* method,       // Http method e.g. "GET", "CONNECT"
        * url,          // "<http[s]>://<hostname>[:port]/[path]"
        * protocol,     // Http proto e.g. "Http/1.1"
        * host,         // Target host
        * path;         // Target path
    int port,           // Target port
        socket,         // Connect file descriptor
        is_ssl;         // Http/HttpS
    SSL_Connection* SSL;// SSL Handle attributes
    HttpHeader* header;
    HttpStore* store;
} HttpRequest;

// Important information from a Http response.
typedef struct{
    void* pad_method,
        * pad_url;
    char* protocol,       // Http proto e.g. HTTP/1.1
        * comment;        // comment about status code
    void* pad_path;
    int status,
        socket,
        is_ssl;
    SSL_Connection* SSL;
    HttpHeader* header;
    HttpStore* store;
} HttpResponse;

// Optional Intermediate form for HTTP req/res
typedef struct{
    void* pad_method,
        * pad_url;
    char* protocol;
    void* pad_host_comment,
        * pad_path;
    int port_status,
        socket,
        is_ssl;
    SSL_Connection* SSL;
    HttpHeader* header;
    HttpStore* store;
} HttpTransaction;

// Possible states for an HttpStore 
enum HttpState{ 
    E_readMethod     =  0,      // reading first line of Http request.
    E_reReadMethod   = (1),     // reading first line of Https request.
    E_readStatus     = (1<<1),  // reading first line Http response.
    E_connect        = (1<<2),  // connecting to host.
    E_readHeader     = (1<<3),  // reading the header.
    E_readContent    = (1<<4),  // reading the content.
    E_readChunks     = (1<<5),  // reading the content.
    E_readMoreChunks = (1<<6),  // reading the content.
    E_continue       = (1<<7),  // Read more data
    E_finished       = (1<<8)   // all data has been processed.
};

// Indicate if the data in the HttpStore has all been parsed 
// or if it still has some left.
#define HTTP_IS_PARSING(x) \
    (((x)&4)|((x)&8)|((x)&16)|((x)&32))

// Get a new store for storing Http data.
///@param flags: pass in one of the macros below.
#define STORE_SIZE (1 << 14)    // initial data cap for Http transaction
#define HTTP_REQ (1 << 0)       // Http transaction is a request
#define HTTP_RES (1 << 1)       // Http transaction is a response
#define HTTPS (1 << 2)          // Http will occur over ssl

#define IS_HTTP_REQ(x)  ((x)&0x1) 
#define IS_HTTP_RES(x)  ((x)&0x2)
#define IS_HTTPS(x)     ((x)&0x4)
HttpStore* newHttpStore(int flags);

// Free an allocated http store
///@param S: pointer to an allocated HttpStore to free.
void freeHttpStore(HttpStore* S);

// Reads from an HTTP Response or Request
// and stores it in an HttpStore
///@param http: a Http Request or Response to read from
int HttpRead(void* http);

// Write bytes from buffer to a HTTP request or response 
///@param http: the http request (client) or response (server)
///             to write to.
///@param buffer: pointer to bytes to be written.
///@param num: the number of bytes to write.
void HttpWrite(void* http, void* buffer, int num);

// Writes the full contents of a http store to stdout
void dumpStore(HttpStore* http_store);


// Print out the headers to stdout of a header 
// linked list for debugging.
///@param header: the first header in linked list.
void printHttpHeaders(HttpHeader **header);


// Parses a string and adds a header to a header
// linked list
///@param header: the first header in linked list.
///@param httpbuf: the string to be parsed.
int HttpParseHeader(HttpHeader** header, char* httpbuf);


// Adds a numeric value and respective string
// for a Http header to a HttpHeader struct,
// Depending on the headertype of the string.
///@param head: the HttpHeader struct to add data to
///@param str: the string to parse.
#define HTTPH_CL 0              // Content-length
#define HTTPH_HOST 1            // Host
#define HTTPH_A_ENCODING 2      // Accept-encoding
#define HTTPH_UNKNOWN 3         // Other
#define HTTPH_T_ENCODING 4
void getHttpHeaderType(HttpHeader* head, char *str);

// Adds a Http header for string representations of a header
void addHttpHeader(HttpHeader** first, char* type, char* data);

// get item from linked list
HttpHeader* getHttpHeader(HttpHeader* first, int type);

// Free a Http linked list structure
///@param first: first item in header linked list
void freeHttpHeaders(HttpHeader** first);

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

// Wraps a TCP connection with Http structure
void HttpWrap(void* http, int sockfd, int flags);

// parses the first line of an Http request and adds
// information to HttpRequest structure
///@param str: the Http request string.
///@param req: pointer to HttpRequest struct to allocate.
int HttpParseMethod(HttpRequest* req, const char* str);

// Same as parseHttpMethod but for Http response.
int HttpParseStatus(HttpResponse* req, const char* str);


// frees an HttpRequest struct.
///@param req: pointer to struct to free.
void freeHttpRequest(HttpRequest* req);

// frees an HttpResponse struct
///@param res: pointer to struct to free.
void freeHttpResponse(HttpResponse* res);


#endif
