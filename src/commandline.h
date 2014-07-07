
#ifndef _COMMANDLINE_H_
#define _COMMANDLINE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

int parseArgs(int _argc, char* argv[], int* cur);

void help();

#endif
