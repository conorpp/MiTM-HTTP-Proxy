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
        "   -append: insert string or files inside match before terminating element",
        "   -prepend: insert string or files inside match after beginning element",
        "   -c <number>: limit the number of times to match and insert. Defaults to infinity.",
        "   -string <string>: pass in a string to insert. ",
        "   -files <file1 file2 ...>: pass in files to insert.",
        "   -matchtag <HTML tag>: Use a built in regex to match an entire HTML tag\n\
                e.g. -matchtag h1 ",
        "   -matchattr <HTML tag>: Use a built in regex to match an entire HTML attribute and it's value\n\
                e.g. -matchattr href ",
        "   -host <hostname>: Set a hostname and edits will only be made to transactions with that host in the http header.",
        "   --<add|replace|block>-headers <header-string>: alter or block server HTTP headers.\n\
                e.g. --add-headers \"Set-Cookie: id=9999\" \"Accept-Language: en-US,en;q=0.5\"\n\
                e.g. --replace-headers \"Last-Modified: Fri, 09 Aug 2013 23:54:35 GMT\"\n\
                e.g. --block-headers \"X-XSS-Protection\" \"Content-Security-Policy\"\n"

        "   --save-client-data [file]: save data sent by client to file.",
        "   --save-server-data [file]: save data sent by server to file.\n\
                A file only needs to be specified once. It will be used for both client and server.",
        "   -headers: include HTTP headers when saving data.",
        "   -ca <CA-file>: Provide a signed central authority certificate to use for MiTM SSL.",
        "   -pk <PK-file>: Provide a private key file for the signed CA file.",
        "   -timeout <number>: Provide a timeout for hangups on client and server transactions in seconds. Default is 10.",
        "   -v <0-5>: Set the verbosity level from 0-5. 0 being the lowest. Default 2.",
        " ",
        "   -gravity: Prox will automatically insert a JavaScript file into websites that gives them gravity.",
        "   -rickroll: Prox will automatically replace all href links with URLS pointing to a Rickroll video.",
        "   -loginfo: Prox will save any data the client sends to a file.",
        "\0"
    };
    for(int i=0; lines[i][0] != '\0'; i++ )
        //Log(LOG1, "%s\n", lines[i]);
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
        die("error: unknown option %s\n", argv[arg]);
    }

    *cur = arg++;
    return CL_NOTHING;
}

static int isArg(char* str){

    for(int i=0; CL_ARGS[i].str[0]; i++){
        if (strncasecmp(str, CL_ARGS[i].str, strlen(CL_ARGS[i].str)) == 0){
            return 1;
        }
    }
    return 0;
}
// 0 is ok, 1 is fail
static int check(int arg, int argc, char *msg){

    if (arg+1 >= argc){
        if (msg != (char*) 0) die(msg);
        else return 1;
    }
    return 0;
}
// 0 is ok, 1 is fail
static int checkFile(char* filename, int kill){
    FILE* f;
    if ( (f=fopen(filename, "r")) == (FILE*) 0){
        if (kill) die("Could not open %s\n", filename);
        else return 1;
    }

    fclose(f);
    return 0;

}
void setProxSettings(int argc, char* argv[]){
    printf("\n");
    static char* files[MAX_FILES];
    static int init = 0;
    if (!init++){
        // initialize
        memset(&Prox, 0, sizeof(struct __SETTINGS__));
        initLogger();
        Prox.options.position = CL_BEFORE;
        Prox.files = files;
        Prox.ssl.enabled++;
        Prox.ssl.certfile = "data/localhost.pem";
        Prox.ssl.privfile = "data/privkey.pem";
        Prox.port = "9999";
        Prox.targetHost = "localhost";
        Prox.match = matchRegex;
        Prox.options.count = -1; // infinity
        Prox.options.timeout = 10; // 10 secs
    }
    int o, cur;
    int claimData = 1;
    int saving = 0;
    long long int scenarios = 0;
    char* tag = (char*) 0;
    char* attr = (char*) 0;
    char* ofile = (char*) 0;
    while( (o=parseArgs(argc, argv, &cur)) != -1){
        switch(o){
            case CL_REGEX:
                claimData = 1;
                check(cur,argc,"Expecting a POSIX regex");
                Prox.regexString = argv[cur+1];
                Prox.regex = newRegex();
                Prox.regex->rStart = compileRegex(Prox.regexString);
                Log(LOG_INFO|LOG1,"compiled regex %s\n", Prox.regexString);
                break;
            case CL_AFTER:
            case CL_BEFORE:
            case CL_REPLACE:
            case CL_APPEND:
            case CL_PREPEND:
                Prox.options.position = o;
            break;
            case CL_STRING:
                claimData = 1;
                check(cur,argc,"Expecting an insertion string");

                if (Prox.filenum == 0)
                    Prox.replaceString = argv[cur+1];
                else
                    die("You can't specify a string to insert and files");
            break;
            case CL_FILES:
                check(cur,argc,"Expecting atleat one file name");
                // normally files come in each arg in array
                while((cur+1<argc) && !isArg(argv[++cur])){
                    Log(LOG4|LOG_DEBUG,"checking file %s\n", argv[cur]);
                    char* file = strtok (argv[cur]," ,");
                    file =argv[cur];
                    claimData++;
                    // Go deeper in case comma seperated filenames in same arg.
                    while(file != (char*) 0){
                        if (++Prox.filenum >= MAX_FILES)
                            die("maximum file amount exceeded.");
                        checkFile(file,1);
                        *(files+Prox.filenum-1) = file;
                        file = strtok((char*)0, " ,");
                    }
                }
                if (Prox.filenum == 0)
                    die("Could not find specified file \"%s\"", argv[cur]);
            break;
            case CL_PORT:
                check(cur,argc,"Expecting port number.");
                int port = atoi(argv[cur+1]);
                if (port < 0 || port > 1<<15){
                    die("Invalid port number %d\n",port);

                }
                Prox.port = argv[cur+1];
            break;
            case CL_CERT_FILE:
                claimData=1;
                check(cur,argc,"Expecting signed central authority certificate filename.");
                checkFile(argv[cur+1], 1);
                Prox.ssl.certfile = argv[cur+1];
            break;
            case CL_PRIV_FILE:
                claimData=1;
                check(cur,argc,"Expecting private key filename.");
                checkFile(argv[cur+1], 1);
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
            case CL_TIMEOUT:
                claimData=1;
                check(cur,argc,"Expecting a value for timeouts.");
                Prox.options.timeout = atoi(argv[cur+1]);
            break;
            case CL_HOST:
                claimData=1;
                check(cur,argc,"Expecting a hostname to compare with HTTP host.");
                Prox.options.host = argv[cur+1];
            break;
            case CL_BLOCK_HEADERS:
            case CL_REPLACE_HEADERS:
            case CL_ADD_HEADERS:
                // --block-headers \"X-XSS-Protection\nContent-Security-Policy\"
                check(cur,argc,"Expecting an HTTP header");
                if (isArg(argv[cur+1]))
                    die("Expecting an HTTP header. Got %s", argv[cur+1]);
                int offset = 1;
                char* header;
                // add each argument as a target header
                while(!isArg((header = argv[cur+offset]))){
                    if ( o == CL_ADD_HEADERS || o==CL_REPLACE_HEADERS){
                        // Include data for adding or replacing target headers
                        char* index = strstr(header, ":");
                        if (index == (char*) 0 || (strlen(index) < 2))
                            die("You need to provide data for each header you add or replace.");
                        char *headertype = header;
                        char *headerdata = index+1;
                        *(index) = '\0';
                        addTargetHeader(headertype, headerdata, o);
                    }else{
                        // don't care about data if your just blocking
                        addTargetHeader(header, "\0", o);
                    }
                    claimData++;
                    // break if reached end of args
                    if (check(cur+offset, argc, (char*)0) != 0)
                        break;
                    offset++;
                }


            break;
            case CL_SAVE_SERVER:
            case CL_SAVE_CLIENT:
              saving = 1;
              // grab a filename if the user supplied one.
              if (check(cur, argc, (char*) 0) == 0)
                if (!isArg(argv[cur+1])){
                  Logger.outputFlags |= LOG_REQ_DATA;
                  ofile = (argv[cur + 1]);
                }
              switch(o){
                case CL_SAVE_SERVER:
                    Logger.outputFlags |= LOG_RES_DATA;
                break;
                case CL_SAVE_CLIENT:
                    Logger.outputFlags |= LOG_REQ_DATA;
                break;
              }
            break;
            case CL_SAVE_HEADERS:
                Logger.outputFlags |= LOG_RES_HEADER;
                Logger.outputFlags |= LOG_REQ_HEADER;
            break;
            case CL_VERBOSITY:
                claimData=1;
                check(cur,argc,"Expecting a verbosity level.");
                Logger.level = 1<<atoi(argv[cur+1]);
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
        die("Could not find host \"%s\": %s\n", Prox.targetHost, gai_strerror(ret));
    }

    // Compile user supplied regex string.
    if (Prox.regexString != (char* )0)
        Prox.options.offset = strlen(Prox.regexString);
    if (Prox.options.findTag || Prox.options.findAttr){
        // Free pre-existing regex if there is one
        if (Prox.regex != (Regex*)0){
            Log(LOG_INFO|LOG1, "warning: supplied regex string is being \
            ignored because an HTML element is specified.\n");
            freeRegex(Prox.regex);
        }
        // Compile special tag finding regex
        if (Prox.options.findTag && !Prox.options.findAttr){
            Prox.regex = compileRegexTag(tag);
            Prox.match = matchRegexTag;
            Prox.options.offset += 3;  // length of </>
            Prox.options.offset += strlen(tag);
        }
        // Compile special tag attr regex
        else if(Prox.options.findAttr){
           Prox.regex = compileRegexAttr(attr, tag);
           Prox.options.offset += 1;  // length of "
        }

    }

    printTargetHeaders();
    // Clear save header bits if REQ/RES is not indicated to be saved
    if ((Logger.outputFlags & LOG_REQ_HEADER) &&
        !(Logger.outputFlags & LOG_REQ_DATA))
      Logger.outputFlags &= (~LOG_REQ_HEADER);

    if ((Logger.outputFlags & LOG_RES_HEADER) &&
        !(Logger.outputFlags & LOG_RES_DATA))
      Logger.outputFlags &= (~LOG_RES_HEADER);

    // Close any old outfiles
    if (Logger.output != (FILE*) 0){
      fclose(Logger.output);
      Logger.output = (FILE*) 0;
    }
    // Open user specified file for output
    if (ofile != (char*) 0)
      Logger.output = fopen(ofile, "w");
    else if (saving){
      // Find a default file to use for output instead
      char filename[100];
      sprintf(filename, "prox.log");
      int num = 1;
      while(checkFile(filename, 0) == 0){
        sprintf(filename, "prox%d.log", num++);
      }
      Log (LOG_INFO|LOG1, "Using output file %s\n", filename);
      Logger.output = fopen(filename, "w");
    }
    // Store a file descriptor for the file stream.
    if (Logger.output != (FILE*) 0){
      Logger.outputfd = fileno(Logger.output);
    }
    // Reset the arg parser
    parseArgs(-1, NULL, NULL);

    // Apply any scenarios specified
    if (scenarios & CL_GRAVITY)
        return setupGravity();
    else if(scenarios & CL_RICKROLL)
        return setupRickRoll();

    /// Debug logging
    int flag = LOG_DEBUG|LOG4;
    Log(flag, "target: %s\n", Prox.targetHost);
    Log(flag, "regex: %s\n", Prox.regexString);
    Log(flag, "str: %s\n", Prox.replaceString);
    if (Prox.options.position==CL_REPLACE)Log(flag, "replace\n");
    else if (Prox.options.position==CL_BEFORE)Log(flag, "before\n");
    else if (Prox.options.position==CL_AFTER)Log(flag, "after\n");

    if(Logger.outputFlags & LOG_REQ_DATA)
        Log(flag, "saving client data\n");
    if(Logger.outputFlags & LOG_RES_DATA)
        Log(flag, "saving server data\n");
    if((Logger.outputFlags & LOG_RES_HEADER) || (Logger.outputFlags & LOG_REQ_HEADER))
        Log(flag, "saving header data\n");


    Log(flag, "files: ");
    for(int t=0; t<Prox.filenum; t++)
        Log(flag, " %s", Prox.files[t]);
    Log(flag, "\n");
    Log(flag, "filenum: %d\n", Prox.filenum);

}
