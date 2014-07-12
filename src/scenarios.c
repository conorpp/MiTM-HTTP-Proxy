#include "scenarios.h"

static int getlength(char** cl){
    int i = 0;
    while(cl[i++][0]);
    return i-1;
}

static void applySettings(char* cl[]){
    int l = getlength(cl);
    for(int i=0; i<l; i++)
        Log(LOG_INFO|LOG1, "%s ", cl[i]);
    Log(LOG_INFO|LOG1,"\n");
    setProxSettings(l, cl);
}

void setupGravity(){
    Log(LOG_INFO|LOG1, " -- Setting up Gravity --\n");
    char *cl[] = {
        (char[]){"./Prox"},
        (char[]){"-files"}, (char[]){"data/gravityscript.html"},
        (char[]){"-matchtag"}, (char[]){"head"},
        (char[]){"-append"},
        (char[]){"-c"},(char[]){"1"},
        "\0"
    };
    applySettings(cl);
}



void setupRickRoll(){

    Log(LOG_INFO|LOG1, " -- Setting up Rickroll --\n");
    char *cl[] = {
        (char[]){"./Prox"},
        (char[]){"-string"}, (char[]){"href=\"http://youtu.be/dQw4w9WgXcQ\""},
        (char[]){"-matchtag"}, (char[]){"a"},
        (char[]){"-matchattr"}, (char[]){"href"},
        (char[]){"-replace"},
        "\0"
    };
    applySettings(cl);
}
