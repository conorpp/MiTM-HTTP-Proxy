
#include "string.h"


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


