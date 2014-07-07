#include "commandline.h"


void Help(){
    char * lines[] = {
        "  --%-- Prox --%--",
        "Usage: ./prox [options] [<string|files>] <target-host>",
        "    target-host: the IP address or domain name of the computer to MiTM attack.",
        "Options:",
        "   -r <regex>: POSIX regular expression to use for matching",
        "   -after: indicate to insert string or files after match",
        "   -before: indicate to insert string or files before match (default)",
        "   -replace: indicate to replace match with string or files",
        "   -string <string>: pass in a string to insert. ",
        "   -files <file1 file2 ...>: pass in files to insert.",
        "   --save-client-data <file>: save data sent by client to file.",
        "   --save-server-data <file>: save data sent by server to file.",
        "   -h: include HTTP headers when saving data.",
        "",
        "   -gravity: Prox will automatically insert a JavaScript file into websites that gives them gravity."
        "   -rickroll: Prox will automatically replace all href links with URLS pointing to a Rickroll video."
        "\0"  
    };
    for(int i=0; lines[i][0]; i++ )
        printf("%s\n", lines[i]);
}
static char* CL_ARGS[] = {
    "-r",
    "-after",
    "-before",
    "-replace",
    "-string",
    "-files",
    "--save-client-data",
    "--save-server-data",
    "-h",
    "-gravity",
    "-rickroll",
    "\0"
};

#define CL_REGEX 1
#define CL_AFTER 2
#define CL_BEFORE 3
#define CL_REPLACE 4
#define CL_STRING 5
#define CL_FILES 6
#define CL_SAVE_CLIENT 7
#define CL_SAVE_SERVER 8
#define CL_SAVE_HEADERS 9
#define CL_GRAVITY 10
#define CL_RICKROLL 11
#define CL_NOTHING 99
int parseArgs(int _argc, char* argv[], int* cur){
    static int arg = 0;
    if (arg >= _argc)
        return -1;
    for(int i=0; CL_ARGS[i][0]; i++){
        if (strncasecmp(argv[arg], CL_ARGS[i], strlen(CL_ARGS[i])) == 0){
            *cur=arg++;
            return (i+1);
        }
    }
    *cur = arg++;
    return CL_NOTHING;
}

int isArg(char* str){
    for(int i=0; CL_ARGS[i][0]; i++){
        if (strncasecmp(str, CL_ARGS[i], strlen(CL_ARGS[i])) == 0){
            return 1;
        }
    }
    return 0;
}

int main(int argc, char* argv[]){

    if (argc<2){
        Help();
        exit(1);
    }
    int o, cur;
    int claimData = 0;
    int pos = CL_BEFORE;
    char** files = (char**)0;
    int filenum = 0;
    char* str = (char*) 0;
    char* regex = (char*) 0;
    char* target = (char*) 0;
    int flags = 0;
    while( (o=parseArgs(argc, argv, &cur)) != -1){
        switch(o){
            case CL_REGEX:
                claimData = 1;
                if (cur+1 < argc)
                    regex = argv[cur+1]; 
                else
                    die("You must provide a POSIX regex after -r");
                break;
            case CL_AFTER:
            case CL_BEFORE:
            case CL_REPLACE:
                pos = o;
            break;
            case CL_STRING:
                claimData = 1;
                if (cur + 1 >= argc)
                    die("You need to provide a string");
                
                if (files == (char**)0)
                    str = argv[cur+1];
                else
                    die("You can't specify a string to insert and files");
            break;
            case CL_FILES:
                printf("files\n");
                claimData = 1;
                if (cur + 1 >= argc)
                    die("You must provide atleat one file name");
                char* pch = strtok (argv[cur+1]," ,");
                int offset = 0;
                while(pch != (char*) 0){
                    filenum++;
                    char* file = pch;
                    FILE* f;
                    if ( (f=fopen(file, "r")) == (FILE*) 0){
                        printf("Could not open %s\n", file);
                        die("");
                    }
                    fclose(f);
                    printf("adding file\n");
                    int size = sizeof(char)*strlen(file) + 1;
                    if (filenum == 1){
                        char *newfile = malloc(size);
                        memmove(newfile, file, size);
                        files = &newfile;
                    }else{
                        char *newfile = realloc(*files, size+offset);
                        memmove(newfile+offset, file, size);
                        files = &newfile;
                    }
                    offset += size; 
                    pch = strtok((char*)0, " ,");
                }
                if (filenum == 0)
                    die("Could not find specified file");
            break;
            case CL_SAVE_CLIENT:
            case CL_SAVE_SERVER:
            case CL_SAVE_HEADERS:
            case CL_GRAVITY:
            case CL_RICKROLL:
                flags |= o;
            break;
            case CL_NOTHING:
                if (!claimData)
                    target = argv[cur];
                claimData = 0;
            break;
        } 
    }
    printf("target: %s\n", target);
    printf("regex: %s\n", regex);
    printf("str: %s\n", str);
    if (pos==CL_REPLACE)printf("replace\n");
    else if (pos==CL_BEFORE)printf("before\n");
    else if (pos==CL_AFTER)printf("after\n");
    printf("files: ");
    for(int t=0; t<filenum; t++)
        printf(" %s", files[t]);
    printf("\n");

    return 0;
    
}
