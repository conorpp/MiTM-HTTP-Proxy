
#include "regex.h"
#include "string.h"
int matchRegex (const char* string, Range* range, Regex* reg)
{
    regmatch_t m[1];
    //printf("--searching %s...\n",string);
    int nomatch = regexec (&reg->r, string, 1, m, 0);
    if (nomatch) {
        printf ("No more matches.\n");
        return nomatch;
    }
    range->start = m[0].rm_so;
    range->end = m[0].rm_eo;
    return 0;
}

Regex* compileRegex(const char* reg){
    Regex *r = malloc(sizeof(Regex));
    memset(r, 0, sizeof(Regex));
    int status = regcomp (&r->r, reg, REG_EXTENDED|REG_NEWLINE);
    if (status != 0) {
        char error_message[1000];
        regerror (status, &r->r, error_message, 1000);
        printf ("Regex error compiling '%s': %s\n",
                reg, error_message);
        exit(1);
    }
    return r;
}


void freeRegex(Regex* r){
    if (r != (Regex*) 0){
        regfree(&r->r);
        free(r);
    }
}
void generateRegexes(){
    memset(&HTML_TAGS, 0, sizeof(struct __TAGS__));
    memset(&HTML_ATTR, 0, sizeof(struct __ATTRIBUTES__));
    HTML_TAGS.a = compileRegex("(<a)[^>]+");
    HTML_TAGS.link = compileRegex("<link[^>]+");
    HTML_TAGS.iframe = compileRegex("<iframe[^>]+");
    HTML_TAGS.script = compileRegex("<script[^>]+");
    HTML_TAGS.body = compileRegex("((<body)((.|\s)*)(</body>))");
    HTML_TAGS.head = compileRegex("((</head>))");

    HTML_ATTR.href = compileRegex("href=\"[^\"]+");
    HTML_ATTR.src = compileRegex("src=\"[^\"]+");
}

void freeRegexes(){
    int ptr_size = sizeof(Regex*);
    int size = (sizeof(struct __TAGS__))/ptr_size;
    printf("---freeing regexes\n");
    for (int i=0; i < size; i++)
        freeRegex( (Regex*)((( PTR_SIZE *)&HTML_TAGS)[i]));
    
    size = (sizeof(struct __ATTRIBUTES__))/ptr_size;
    
    for (int i=0; i < size; i++)
        freeRegex( (Regex*)((( PTR_SIZE *)&HTML_ATTR)[i]));
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
#if 0
int main(int argc, char ** argv)
{
    const char * regex_text;
    char * find_text;
    if (argc < 2) {
        printf("you forget text\n");
        exit(1);
    }
    else{
        find_text = argv[1];
    }
    generateRegexes();
    char *html = "<html><head><title>hi</title></head><body><h1>hello</h1></body></html>\n";
    char* inject = "href=\"http://it worked\"";
    int newlength;
    Range r;
    findBodyEnd(html, &r);
    char* files[] = {"../gravityscript.html", "../script2.html"};
    char *result=insertFiles(findBodyEnd,
        html, strlen(html), &newlength,files, 1 );
    printf("result: %s\n", result);
    //char* newstring = replaceAll(findLink, find_text, strlen(find_text), &newlength, inject);
    //printf("after replacement: %s\n", newstring);
    //printf("new length: %d, strlen: %d\n", newlength, (int)strlen(newstring));
    freeRegexes();

    return 0;
}
#endif
