#include <stdio.h>
#include <stdlib.h>

#include <string.h>

// buffered reader

typedef struct{
    int (*read)(void* sockfd, void* buffer, int nbytes);
    char delim;
    int nbytes;
    void* sockfd;
    int chunkSize;
    char* buf;
    int leftover;
} BReader;

BReader* openBReader(int (*reader)(void* sockfd, void* buffer, int nbytes), void* sockfd, int nbytes, char delimiter, int chunkSize){
    BReader* readbuffer = malloc(sizeof(BReader));

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

void closeBReader(BReader* r){
    if (r != (BReader*) 0){
        if (r->buf != (char*) 0)
            free(r->buf);
        free(r);
    }
}

int readBuffer(BReader * reader, char *buffer){
    int total = 0, r, i;

    if (reader->leftover){
        for(r=0; r < reader->leftover; r++){
            buffer[r] = reader->buf[r];
            if (reader->buf[r] == reader->delim){
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
            if (buffer[total-1] == reader->delim ){
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

int RAND;
char* response;
char* content;
int responseL;
int contentL;
int Read(int sockfd,char*buf, int nbytes){
    static int pos = 0;
    int r = 0;
    for(int i=0; pos<RAND && i<nbytes; i++){
        if (!response[pos]){
            if (response != content){
                response = content;
                pos=0;
            }
            break;
        }
        buf[i] = response[pos];
        pos++;
        r ++;
    }
    return r;
}

int main(int argc, char* argv[]){
    response ="GET / HTTP 1.0\r\nHost: www.google.com\r\nUser-Agent: Mozilla (11.0) Ubuntu wowo\r\nData-type: text/html,gzip,*/*\r\nContent-length: 2349\r\n\r\n";
    
    content = "<html><head><title>Conorpp</title></head><body><h1>hello world</h1><script>alert(\"hr\");</script> </body> </html>";
    responseL = strlen(response);
    contentL = strlen(content);
    if(argc<2){
        printf("you forgot RAND int\n");
    }
    RAND = atoi(argv[1]);
    // func, sockfd, bufsize, delimiter, chunksize
    BReader* a = openBReader(Read, 19, 30, '\n', 8);
    char buff[1024];
    int b=0;
    int l = RAND;
    int total=0;
    while((b = readBuffer(a, buff)) > 0){
      total += b;
      printf("%s", buff);
    }
    printf("\ntotal:%d\n",total);
    closeBReader(a);
    return 0;
}









