#ifndef _PROXY_H_
#define _PROXY_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include "utils.h"



/* Functionaly specific to proxying
* */

// Decodes a deflate or gzip buffer.
///@param gzip: the compressed buffer
///@param length: the length of gzip in bytes
void decodeGzip(char** gzip, int *length);




#endif
