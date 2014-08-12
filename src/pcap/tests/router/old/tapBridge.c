#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>

#include <linux/if_tun.h>

extern int errno;

int bridge_term = 0;
int f1, f2;

void sig_io(int sig) 
{
    static char buf[1600];
    register int r;

    while( (r=read(f1, buf, sizeof(buf))) > 0 )
        write(f2, buf, r);
    if( r < 0 && (errno != EAGAIN && errno != EINTR) ) {
        bridge_term = 1;
        return;
    }

    while( (r=read(f2, buf, sizeof(buf))) > 0 )
        write(f1, buf, r);
    if( r < 0 && (errno != EAGAIN && errno != EINTR) ) {
        bridge_term = 1;
        return;
    }
}

int main(int argc, char *argv[])
{
    struct sigaction sa;
    char buf[20];

    if(argc < 2) {
        printf("Usage: bridge tap|tun\n");
        exit(1);
    }

    sprintf(buf,"/dev/%s%d",argv[1],0);
    f1 = open(buf, O_RDWR);

    sprintf(buf,"/dev/%s%d",argv[1],1);
    f2 = open(buf, O_RDWR);

    ioctl(f1, TUNSETNOCSUM, 1);
    ioctl(f2, TUNSETNOCSUM, 1);

    fcntl(f1, F_SETFL, O_NONBLOCK | O_ASYNC);
    fcntl(f2, F_SETFL, O_NONBLOCK | O_ASYNC);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_io;
    sigaction(SIGIO, &sa, NULL); 

    while( !bridge_term )
        sleep(1000); 
}
