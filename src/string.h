/* Additional string functionality
* */

#include <string.h>    // strings
#include "regex.h"     // regexes

#ifndef _STRING_H_
#define _STRING_H_

// replaced a specified range in a string with a substr.
// A new string is allocated and returned.  This must be
// freed by the user.
char* replace(char* string, int len, char* substr, int sublen, Range* r, int* newlength);

// Replace all occurances of a string using a regex function pointer
// returns allocated string with all replacedments.  Must be
// freed by user.
char* replaceAll(int (*regFunc)(const char*, Range*), char * string, int length, int* newlength, char* substr);


char* insertFiles(int (*regFunc)(const char*, Range*),
        char * string, int length, int* newlength, char* files[], int filenum);


#endif
