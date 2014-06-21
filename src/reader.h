#ifndef READER_H
#define READER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Generic API for reading from file descriptor like buffers (sockets/openSSL).
 * */

// Header for a Reader.
typedef struct{

    int (*read)(void* sockfd,   // Function pointer to the read function
                void* buffer, 
                int nbytes);
    char delim;                 // Delimiting character
    int nbytes;                 // Max number of bytes to read
    void* sockfd;               // file descripter / buffer identifier
    int chunkSize;              // max byte chunks to read internally
    char* buf;                  // buffer
    int leftover;               // buffer offset
} Reader;

// Initialize a Reader
///@param reader: pointer to function to read from
///@param sockfd: the file descriptor or identifier for read function
///@param nbytes: the maximum number of bytes for Reader to read into
///               buffer at a time.
///@param delimiter: a character that the reader will stop after.
///@param chunkSize: the number of bytes to read at a time internally.
///@return: Pointer to initialized Reader.
#define READER_NO_DELIM 19
Reader* openReader(
    int (*reader)(void* sockfd, void* buffer, int nbytes), 
    void* sockfd, int nbytes, char delimiter, int chunkSize);

// Deallocates a Reader.  This does not close
// the file descriptor in the reader.
///@param r: Pointer to Reader. 
void closeReader(Reader* r);

//Reads into a buffer using an allocated Reader.
///@param reader: the Reader to use to read.
///@param buffer: the buffer to read into.
///@return: the number of bytes read into buffer.
int readBuffer(Reader * reader, char *buffer);

#endif

