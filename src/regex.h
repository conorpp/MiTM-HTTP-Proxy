/* Regex functionality biased for HTML parsing
* */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <regex.h>
#include "utils.h"

#ifndef REGEX_H_
#define REGEX_H_

#define NO_MATCH -1

typedef struct{
    int start;
    int end;
} Range;

typedef struct{
    regex_t* rStart;
    regex_t* rEnd;
} Regex;


struct __TAGS__{
     regex_t* a,
          * link,
          * iframe,
          * body,
          * head,
          * script;
} HTML_TAGS;

struct __ATTRIBUTES__{
    regex_t* href,
         * src;
} HTML_ATTR;

void generateRegexes();


int matchRegex_t (const char* string, Range* range, regex_t* reg);
int matchRegex (const char* string, Range* range, Regex* reg);

int matchRegexTag(const char* string, Range* r, Regex* rgx);

regex_t* compileRegex(const char* reg);

Regex* compileRegexTag(const char* tag);

Regex* compileRegexAttr(const char* attr);

Regex* newRegex();

void freeRegex(Regex* r);

void freeRegexes();

int findLink(const char* string, Range* r);
int findBodyEnd(const char * string, Range* r);
int findHeadEnd(const char * string, Range* r);

#endif
