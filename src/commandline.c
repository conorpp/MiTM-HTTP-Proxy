#include "commandline.h"
#include "scenarios.h"

void Help(){
    char * lines[] = {
        "  --%-- Prox --%--",
        "Usage: ./prox [options] [<string|files>] <target-host>",
        "    target-host: the IP address or domain name of the computer to MiTM attack.",
        "Options:",
        "   -p <port>: Port to listen on.",
        "   -r <regex>: POSIX regular expression to use for matching",
        "   -after: indicate to insert string or files after match",
        "   -before: indicate to insert string or files before match (default)",
        "   -replace: indicate to replace match with string or files",
        "   -append: insert string or files inside match",
        "   -c <number>: limit the number of times to match and insert. Defaults to inserting after every match.",
        "   -string <string>: pass in a string to insert. ",
        "   -files <file1 file2 ...>: pass in files to insert.",
        "   -matchtag <HTML tag>: Use a built in regex to match an entire HTML tag\n\
                e.g. -matchtag h1 ",
        "   -matchattr <HTML tag>: Use a built in regex to match an entire HTML attribute and it's value\n\
                e.g. -matchattr href ",
        "   --save-client-data <file>: save data sent by client to file.",
        "   --save-server-data <file>: save data sent by server to file.",
        "   -h: include HTTP headers when saving data.",
        "   -ca <CA file>: Provide a signed central authority certificate to use for MiTM SSL.",
        "   -pk <PK file>: Provide a private key file for the signed CA file.",
        "",
        "   -gravity: Prox will automatically insert a JavaScript file into websites that gives them gravity."
        "   -rickroll: Prox will automatically replace all href links with URLS pointing to a Rickroll video."
        "\0"  
    };
    for(int i=0; lines[i][0]; i++ )
        printf("%s\n", lines[i]);
}

int parseArgs(int _argc, char* argv[], int* cur){
    static int arg = 0;
    if (_argc == -1){
        arg = 0;
        return -1;
    }
    if (arg >= _argc)
        return -1;
    for(int i=0; CL_ARGS[i].str[0]; i++){
        if (strcmp( CL_ARGS[i].str, argv[arg]) == 0){
            *cur=arg++;
            return CL_VAL(i);
        } 
    }
    if(argv[arg][0] == '-'){
        fprintf(stderr, "error: unknown option %s\n", argv[arg]);
        die("");
    }

    *cur = arg++;
    return CL_NOTHING;
}

static int isArg(char* str){
    printf("Cchekinf arg\n");
    for(int i=0; CL_ARGS[i].str[0]; i++){
        if (strncasecmp(str, CL_ARGS[i].str, strlen(CL_ARGS[i].str)) == 0){
            return 1;
        }
    }
    return 0;
    printf("cehcekd arg\n");
}

static void check(int arg, int argc, char *msg){
    if (arg+1 >= argc)
        die(msg);
}
static void checkFile(char* filename){
    FILE* f;
    if ( (f=fopen(filename, "r")) == (FILE*) 0){
        printf("Could not open %s\n", filename);
        die("");
    }
    fclose(f);

}
void setProxSettings(int argc, char* argv[]){
    static char* files[MAX_FILES];
    static int init = 0;
    if (!init++){
        memset(&Prox, 0, sizeof(struct __SETTINGS__));
        Prox.options.position = CL_BEFORE;
        Prox.files = files;
        Prox.ssl.enabled++;
        Prox.ssl.certfile = "data/localhost.pem";
        Prox.ssl.privfile = "data/privkey.pem";
        Prox.port = "9999";
        Prox.targetHost = "localhost";
        Prox.match = matchRegex;
    }
    int o, cur;
    int claimData = 1;
    long long int scenarios = 0;
    char* tag = (char*) 0;
    char* attr = (char*) 0;
    while( (o=parseArgs(argc, argv, &cur)) != -1){
        switch(o){
            case CL_REGEX:
                claimData = 1;
                check(cur,argc,"Expecting a POSIX regex");
                Prox.regexString = argv[cur+1]; 
                Prox.regex = newRegex();
                Prox.regex->rStart = compileRegex(Prox.regexString);
                break;
            case CL_AFTER:
            case CL_BEFORE:
            case CL_REPLACE:
            case CL_APPEND:
                Prox.options.position = o;
            break;
            case CL_STRING:
                claimData = 1;
                check(cur,argc,"Expecting a string");
                
                if (Prox.filenum == 0)
                    Prox.replaceString = argv[cur+1];
                else
                    die("You can't specify a string to insert and files");
            break;
            case CL_FILES:
                printf("checking file %s\n", argv[cur]);
                check(cur,argc,"Expecting atleat one file name");
                printf("");
                while((cur+1<argc) && !isArg(argv[++cur])){
                    printf("checking file+1 %s\n", argv[cur]);
                    char* file = strtok (argv[cur]," ,");
                    file =argv[cur];
                    printf("looking at %s\n",file);
                    claimData++;
                    while(file != (char*) 0){
                        if (++Prox.filenum >= MAX_FILES)
                            die("maximum file amount exceeded.");
                        checkFile(file);
                        *(files+Prox.filenum-1) = file;
                        file = strtok((char*)0, " ,");
                    }
                }
                if (Prox.filenum == 0)
                    die("Could not find specified file");
            break;
            case CL_PORT:
                check(cur,argc,"Expecting port number.");
                int port = atoi(argv[cur+1]);
                if (port < 0 || port > 1<<15){
                    fprintf(stderr, "Invalid port number %d\n",port);
                    die("");
                }
                Prox.port = argv[cur+1];
            break;
            case CL_CERT_FILE:
                claimData=1;
                check(cur,argc,"Expecting signed central authority certificate filename.");
                checkFile(argv[cur+1]);
                Prox.ssl.certfile = argv[cur+1];
            break;
            case CL_PRIV_FILE:
                claimData=1;
                check(cur,argc,"Expecting private key filename.");
                checkFile(argv[cur+1]);
                Prox.ssl.privfile = argv[cur+1];
            break;
            case CL_TAG:
                claimData=1;
                check(cur,argc,"Expecting HTML tag.");
                tag = argv[cur+1];
                Prox.options.findTag++;
            break;
            case CL_ATTR:
                claimData=1;
                check(cur,argc,"Expecting HTML attribute.");
                attr = argv[cur+1];
                Prox.options.findAttr++;
            break;
            case CL_COUNT:
                claimData=1;
                check(cur,argc,"Expecting a number for limiting insertions.");
                Prox.options.count = atoi(argv[cur+1]);
            break;
            case CL_SAVE_CLIENT:
                Prox.options.saveClient++;
            break;
            case CL_SAVE_SERVER:
                Prox.options.saveServer++;
            break;
            case CL_SAVE_HEADERS:
                Prox.options.saveHeaders++;
            break;
            case CL_GRAVITY:
            case CL_RICKROLL:
                scenarios |= o;
            break;
            case CL_NOTHING:
                if (claimData-- <= 0){
                    Prox.targetHost = argv[cur];
                    claimData = 0;
                }
            break;
        } 
    }
    int ret;
    if ((ret=hostIsAlive(Prox.targetHost)) != 0){
        fprintf(stderr, "Could not find host \"%s\": %s\n", Prox.targetHost, gai_strerror(ret));
        die("");
    }
    if (Prox.regexString != (char* )0)
        Prox.options.offset = strlen(Prox.regexString);
    if (Prox.options.findTag || Prox.options.findAttr){
        if (Prox.regex != (Regex*)0){
            printf("warning: supplied regex string is being \
            ignored because an HTML element is specified.\n");
            freeRegex(Prox.regex);
        }
        if (Prox.options.findTag && !Prox.options.findAttr){
            Prox.regex = compileRegexTag(tag); 
            Prox.match = matchRegexTag;
            Prox.options.offset += 3; 
        }
        else if(Prox.options.findAttr){
           Prox.regex = compileRegexAttr(attr, tag); 
           Prox.options.offset += 1; 
        }

    }

    parseArgs(-1, NULL, NULL);
    if (scenarios & CL_GRAVITY)
        setupGravity();
    else if(scenarios & CL_RICKROLL)
        setupRickRoll();
#if 0
    printf("target: %s\n", Prox.targetHost);
    printf("regex: %s\n", Prox.regexString);
    printf("str: %s\n", Prox.replaceString);
    if (Prox.options.position==CL_REPLACE)printf("replace\n");
    else if (Prox.options.position==CL_BEFORE)printf("before\n");
    else if (Prox.options.position==CL_AFTER)printf("after\n");

    if(Prox.options.saveClient)
        printf("saving client data\n");
    if(Prox.options.saveServer)
        printf("saving server data\n");
    if(Prox.options.saveHeaders)
        printf("saving header data\n");


    printf("files: ");
    for(int t=0; t<Prox.filenum; t++)
        printf(" %s", Prox.files[t]);
    printf("\n");
#endif
}
