#include "syscall.h"

#define SYS_WRITE 1

int write(int fd, const void *buf, int len) {
    int retval;
    __asm__ volatile("syscall\n\t" : "=a"(retval) : "a"(SYS_WRITE), "D"(fd), "S"(buf), "d"(len));
    return retval;
}