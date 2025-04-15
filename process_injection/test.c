#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main()
{   
    int i;

    pid_t uid = getuid();
    printf("Uid : %d\n", uid);
    printf ("PID: %d\n", (int)getpid());
    while(1) {
        write (1, "Hello World\n", 12);
        sleep(2);
    }
    return 0;
}