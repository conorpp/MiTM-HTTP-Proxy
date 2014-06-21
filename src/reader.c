#include "reader.h"

Reader* openReader(int (*reader)(void* sockfd, void* buffer, int nbytes), void* sockfd, int nbytes, char delimiter, int chunkSize){
    Reader* readbuffer = malloc(sizeof(Reader));

    readbuffer->read      = reader;
    readbuffer->delim     = delimiter;
    readbuffer->sockfd    = sockfd;
    readbuffer->nbytes    = nbytes;
    readbuffer->chunkSize = chunkSize;
    readbuffer->buf       = malloc(chunkSize);
//    printf("chunksize: %d\n", chunkSize);
    readbuffer->leftover  = 0;
    if (nbytes < chunkSize){
        fprintf(stdout, "getBufferedReader: warning: nbytes is less than chunksize.\n");
    }
    return readbuffer;
}

void closeReader(Reader* r){
    if (r != (Reader*) 0){
        if (r->buf != (char*) 0)
            free(r->buf);
        free(r);
    }
}

int readBuffer(Reader* reader, char *buffer){
    int total = 0, r, i;

    if (reader->leftover){
        for(r=0; r < reader->leftover; r++){
            buffer[r] = reader->buf[r];
            if (reader->buf[r] == reader->delim 
                && reader->buf[r] != READER_NO_DELIM){
                total = r+1;
                reader->leftover -= total;
                if (reader->leftover)  
                    memmove(reader->buf, &reader->buf[r+1], reader->leftover);
                goto done;
            }
        }
        total = reader->leftover;
        reader->leftover = 0;
    }
    while( (r = reader->read(reader->sockfd, &buffer[total], reader->chunkSize)) > 0 ){
        for (i=0; i<r; i++){
            total++;
            if (buffer[total-1] == reader->delim 
                && buffer[total-1] != READER_NO_DELIM){
                reader->leftover = r - (i + 1);
                memmove(reader->buf, &buffer[total], reader->leftover);
                goto done;
            }
        }
        if (total + reader->chunkSize > reader->nbytes)
            goto done;
    }
    done:
    buffer[total] = '\0';

    return total;
}







