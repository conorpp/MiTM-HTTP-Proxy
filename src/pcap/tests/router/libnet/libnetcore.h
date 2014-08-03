/*
 *  $Id: libnet_test.h,v 1.3 2004/01/29 21:17:16 mike Exp $
 *
 *  libnet_test.h
 *
 *  Copyright (c) 1998 - 2001 Mike D. Schiffman <mike@infonexus.com>
 */

#ifndef __LIBNET_TEST_H
#define __LIBNET_TEST_H

#if (HAVE_CONFIG_H)
#include "config.h"
#endif

#include "libnet.h"

#if (_WIN32) || (__CYGWIN__)
#else
# include <netinet/in.h>
#endif

#define libnet_timersub(tvp, uvp, vvp)                                  \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
                if ((vvp)->tv_usec < 0) {                               \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_usec += 1000000;                      \
                }                                                       \
        } while (0)



void usage(char *);

#if defined(__WIN32__)
#include <getopt.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#ifndef _WIN32
#include <sys/time.h>
#endif
#if defined(__GNUC__)         /* mingw compiler */
extern __attribute__((dllimport)) char *optarg;
#else   /* assume msvc */
#ifndef _WIN32
extern __dllspec(dllimport) char *optarg;
#endif
#endif
#endif  /* __WIN32__ */

#endif  /* __LIBNET_TEST_H */

/* EOF */
