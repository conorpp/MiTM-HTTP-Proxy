#include <stdio.h>
int main(){

#if PROXY
    printf("PROXY\n");
#else
    printf("no PROXY\n");
#endif

return 0;

}
