#ifndef _TUN_H_
#define _TUN_H_
#include <sys/ioctl.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/if_tun.h>


// Register a TUN or TAP device
int tun_alloc(char *dev, int flags);

#endif
