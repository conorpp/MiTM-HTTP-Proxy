
#include "string.h"
#include "utils.h"


char* replace(char* string, int len, char* substr, int sublen, 
            Range* r, int* newlength){
    char* s1 = string;
    int s1l = r->start;

    char* s3 = string + r->end;
    int s3l = len - r->end;

    *newlength = s1l + s3l + sublen;
    char* newstring = malloc(*newlength + 1);
    memmove(newstring, s1, s1l);
    memmove(newstring + s1l, substr, sublen);
    memmove(newstring + s1l + sublen, s3, s3l + 1);
    
    return newstring;
}


char* replaceAll(int (*regFunc)(const char*, Range*),
        char * string, int length, int* newlength, char* substr){
    
    Range range;
    memset(&range, 0, sizeof(Range));
    
    char* replaced = malloc(length+1);
    memmove(replaced, string, length+1);

    *newlength = length;
    char* tmp;
    int offset = 0;
    int sublen = strlen(substr);
    
    while (regFunc(replaced + range.start, &range) == 0){
        
        range.start += offset;
        range.end += offset;
        offset = range.start;
        tmp = replaced;
        
        replaced = replace(replaced, *newlength, 
                            substr, sublen, &range, newlength);

        if (tmp != (char*)0)
            free(tmp);
    }
    return replaced;
}

char* insertFiles(int (*regFunc)(const char*, Range*),
        char * string, int length, int* newlength, char* files[], int filenum){
    char *strbuf;
    Range range;
    memset(&range, 0, sizeof(Range));
    
    //char* replaced;// = malloc(length+1);
    //memmove(replaced, string, length+1);

    *newlength = length;
    char* orig = string;
    char* tmp;
    
    if ( regFunc(string, &range) != 0) 
        return string;
    for (int i=0; i<filenum; i++){
        
        tmp = string;
        FILE* f = fopen(files[i], "r");
        if (f == (FILE*)0){
            printf("could not open file %s", files[i]);
            exit(2);
        }
        
        // obtain file size:
        fseek (f , 0 , SEEK_END);
        long int size = ftell (f);
        rewind (f);
        
        strbuf = malloc(size);
        int r = fread (strbuf,1,size,f);
        if (r != size)
            die("file was read incorrectly\n");
        string = replace(string, *newlength, strbuf, size, &range, newlength);
        range.start += size;
        range.end += size;
        
        if (tmp != (char*) 0 && tmp != orig)
            free(tmp);
    }
    return string;
 
}





