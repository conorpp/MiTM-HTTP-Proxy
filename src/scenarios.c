#include "scenarios.h"

static int getlength(char** cl){
    int i = 0;
    while(cl[i++][0]);
    return i-1;
}

static void applySettings(char* cl[]){
    int l = getlength(cl);
    for(int i=0; i<l; i++)
        cl[i] = strdup(cl[i]);
    for(int i=0; i<l; i++)
        printf("%s ", cl[i]);
    printf("\n");
    setProxSettings(l, cl);
}   

void setupGravity(){
    printf(" -- Setting up Gravity --\n");
    char *cl[] = {
        "./Prox",
        "-files", "data/gravityscript.html",
        "-matchtag", "head",
        "-append",
        "\0"
    };
    applySettings(cl);
}



void setupRickRoll(){

    printf(" -- Setting up Rickroll --\n");
    char *cl[] = {
        "./Prox",
        "-string", "href=\"http://youtu.be/dQw4w9WgXcQ\"",
        "-matchtag", "a",
        "-matchattr", "href",
        "-replace",
        "\0"
    };
    applySettings(cl);
}

