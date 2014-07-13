
#include "regex.h"
#include "string.h"

int matchRegex_t (const char* string, Range* range, regex_t* reg)
{
    regmatch_t m[1];
    int nomatch = regexec (reg, string, 1, m, 0);
    if (nomatch) {
        Log (LOG_DEBUG|LOG1, "No more matches. (%d)\n",nomatch);
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
        die("Regex error compiling '%s': %s\n",
                reg, error_message);
    }
    return r;
}

Regex* compileRegexTag(const char* tag){
    char buf[500];
    Regex* rgx = newRegex();
    if (strlen(tag)>450)
        die("HTML element is too large");

    sprintf(buf,"<%s[^>]*",tag);
    rgx->rStart = compileRegex(buf);
    rgx->rStartTerm = ">";
    Log(LOG_INFO|LOG1, "compiled regex %s",buf);

    sprintf(buf,"</%s>",tag);
    rgx->rEnd = compileRegex(buf);
    rgx->rEndTerm = ">";
    Log(LOG_INFO|LOG1, " (...) %s\n",buf);

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
    rgx->rStartTerm = ">";
    Log(LOG_INFO|LOG1, "compiled regexes %s",buf);

    sprintf(buf,"((%s=\"[^\"]+\"))", attr);
    rgx->rEnd = compileRegex(buf);
    rgx->rEndTerm = "\"";
    Log(LOG_INFO|LOG1, " and %s\n",buf);
    
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
