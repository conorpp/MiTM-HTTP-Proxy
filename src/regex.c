
#include "regex.h"
#include "string.h"

int matchRegex_t (const char* string, Range* range, regex_t* reg)
{
    regmatch_t m[1];
    int nomatch = regexec (reg, string, 1, m, 0);
    if (nomatch) {
        printf ("No more matches. (%d)\n",nomatch);
        return nomatch;
    }
    range->start = m[0].rm_so;
    range->end = m[0].rm_eo;
    return 0;
}

int matchRegex (const char* string, Range* range, Regex* reg){
    if (reg->rEnd == (regex_t*) 0)
        return matchRegex_t(string, range, reg->rStart);
    int ec = 0;
    Range offset;
    
    if ( (ec=matchRegex_t(string, &offset, reg->rStart)) == 0){
        ec = matchRegex_t(string + offset.start, range, reg->rEnd);
    }else{
        return ec;
    }
    range->start += offset.start;
    range->end += offset.start;
    return ec;
}

regex_t* compileRegex(const char* reg){
    regex_t *r = malloc(sizeof(regex_t));
    int status = regcomp (r, reg, REG_EXTENDED|REG_NEWLINE);
    if (status != 0) {
        char error_message[1000];
        regerror (status, r, error_message, 1000);
        printf ("Regex error compiling '%s': %s\n",
                reg, error_message);
        exit(1);
    }
    return r;
}

Regex* compileRegexTag(const char* tag){
    char buf[500];
    Regex* rgx = newRegex();
    if (strlen(tag)>450)
        die("HTML element is too large");
    sprintf(buf,"<%s[^>]*",tag);
    printf("compiled regex %s",buf);
    rgx->rStart = compileRegex(buf);
    sprintf(buf,"</%s>",tag);
    rgx->rEnd = compileRegex(buf);
    printf(" (...) %s\n",buf);
    return rgx;
}
Regex* compileRegexAttr(const char* attr, const char* tag){
    char buf[1000];
    if (strlen(attr)>950)
        die("HTML element is too large");
    Regex* rgx = newRegex();
    if (tag != (char*)0)
        sprintf(buf, "<%s[^>]*>", tag);
    else
        sprintf(buf, "<[^>]*>");
    rgx->rStart = compileRegex(buf);
    printf("compiled regexes %s",buf);
    sprintf(buf,"((%s=\"[^\"]+\"))", attr);
    rgx->rEnd = compileRegex(buf);
    printf(" and %s\n",buf);
    return rgx;
}

Regex* newRegex(){
    Regex* rgx = malloc(sizeof(Regex));
    memset(rgx, 0, sizeof(Regex));
    return rgx;
};

void freeRegex(Regex* r){
    if (r != (Regex*) 0){
        if (r->rStart != (regex_t*)0)
            regfree(r->rStart);
        if (r->rEnd != (regex_t*)0)
            regfree(r->rEnd);
        free(r);
    }
}
/*
void generateRegexes(){
    memset(&HTML_TAGS, 0, sizeof(struct __TAGS__));
    memset(&HTML_ATTR, 0, sizeof(struct __ATTRIBUTES__));
    HTML_TAGS.a = compileRegex("(<a)[^>]+");
    HTML_TAGS.link = compileRegex("<link[^>]+");
    HTML_TAGS.iframe = compileRegex("<iframe[^>]+");
    HTML_TAGS.script = compileRegex("<script[^>]+");
    HTML_TAGS.body = compileRegex("((<body)((.|\\s)*)(</body>))");
    HTML_TAGS.head = compileRegex("((</head>))");

    HTML_ATTR.href = compileRegex("href=\"[^\"]+");
    HTML_ATTR.src = compileRegex("src=\"[^\"]+");
}

void freeRegexes(){
    int ptr_size = sizeof(Regex*);
    int size = (sizeof(struct __TAGS__))/ptr_size;
    printf("---freeing regexes\n");
    for (int i=0; i < size; i++)
        regfree( (regex_t*)((( PTR_SIZE *)&HTML_TAGS)[i]));
    
    size = (sizeof(struct __ATTRIBUTES__))/ptr_size;
    
    for (int i=0; i < size; i++)
        regfree( (regex_t*)((( PTR_SIZE *)&HTML_ATTR)[i]));
    printf("---freed regexes");
}


int findBodyEnd(const char * string, Range* r){
    if (matchRegex(string, r, HTML_TAGS.body) != 0)
       return 1;
    r->start = (r->end -= 7);// strlen(</body>)
    printf("found boday @ %d:%d\n%s", r->start, r->end,string);
    return 0;
}

int findHeadEnd(const char * string, Range* r){
    if (matchRegex(string, r, HTML_TAGS.head) != 0){
       return 1;
    }
    r->start = (r->end -= 7);// strlen(</head>)
    //printf("found match\n");
    return 0;
}

int findLink(const char* string, Range* r){
    static Range firstRun;
    if ( matchRegex(string, &firstRun, HTML_TAGS.a) != 0 )
        return 1;
    if ( matchRegex(string + firstRun.start, r, HTML_ATTR.href) != 0)
        return 1;
    r->start += firstRun.start + 6; // strlen(href=")
    r->end += firstRun.start;
    return 0;
}
*/
int matchRegexTag(const char* string, Range* r, Regex* rgx){
    int offset1 = 0, offset2 = 0, ec = 0;
    Range endTag, futureTag;
    ec = matchRegex_t(string, r, rgx->rStart);
    if (ec != 0)
        return ec;
    offset2 += r->end;
    ec = matchRegex_t(string, &endTag, rgx->rEnd); 
    if (ec != 0)
        return ec;
    ec = matchRegex_t(string + offset2, &futureTag, rgx->rStart); 
    if (ec != 0) 
        goto done;
    
    while (endTag.start+offset1  > futureTag.start+offset2){
        ec = matchRegex_t(string +(offset2 += futureTag.end),
                            &futureTag, rgx->rStart);
        ec = matchRegex_t(string + (offset1 += endTag.end),
                                    &endTag, rgx->rEnd); 
        if (ec != 0)
            return ec;
    }
    done:
    r->end = endTag.end + offset1;
    return 0;
    
}
#if 0
int main(int argc, char ** argv)
{
    const char * regex_text;
    char * find_text;
    if (argc <2 ) {
        printf("you forget text\n");
        exit(1);
    }
    else{
        find_text = argv[1];
    }
    Range r;
    // Regex* rgx = compileHTMLTagRegex(argv[1]);
    Regex* rgx = compileRegexAttr(argv[1]);

    char buf[20000];
    // obtain file size:
    FILE *f = fopen("test.html", "r");
    fseek (f , 0 , SEEK_END);
    long int size = ftell (f);
    rewind (f);

    fread (buf,1,size,f);
    matchRegex(buf, &r, rgx);
/*
    int offset1 = 0;
    int offset2 = 0;
    matchRegex(buf, &r1, rgx1);
    offset2 += r1.end;
    matchRegex(buf + offset2, &r3, rgx1); //after
    matchRegex(buf , &r2, rgx2); //end
    printf("r2 %d > r3 %d\n", r2.start, r3.start);
    int tmp = 0;
    while (r2.start+offset1  > r3.start+offset2){
        matchRegex(buf +(offset2 += r3.end), &r3, rgx1);
        matchRegex(buf + (offset1 += r2.end), &r2, rgx2); //end
        printf("r2 %d > r3 %d\n", r2.start , r3.start);
    }
    Range r;
    r.start = r1.start;
    r.end = r2.end + offset1;
*/
    printf("found match:\n");
    fflush(stdout);
    write(fileno(stdout), buf + r.start, r.end - r.start);

    printf("\n");
    return 0;
}
#endif
