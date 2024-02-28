#include "syscall.h"

#define SYS_READ         0x00
#define SYS_WRITE        0x01
#define SYS_OPEN         0x02
#define SYS_CLOSE        0x03
#define SYS_GETTIMEOFDAY 0x60

int read(int fd, void *buf, int len) {
    int retval;
    __asm__ volatile("syscall\n\t" : "=a"(retval) : "a"(SYS_READ), "D"(fd), "S"(buf), "d"(len));
    return retval;
}

int write(int fd, const void *buf, int len) {
    int retval;
    __asm__ volatile("syscall\n\t" : "=a"(retval) : "a"(SYS_WRITE), "D"(fd), "S"(buf), "d"(len));
    return retval;
}

int open(const char *path, int mode) {
    int retval;
    __asm__ volatile("syscall\n\t" : "=a"(retval) : "a"(SYS_OPEN), "D"(path), "S"(mode), "d"(0));
    return retval;
}

int close(int fd) {
    int retval;
    __asm__ volatile("syscall\n\t" : "=a"(retval) : "a"(SYS_CLOSE), "D"(fd));
    return retval;
}

int gettimeofday(timeval *tv, timezone *tz) {
    int retval;
    __asm__ volatile("syscall\n\t" : "=a"(retval) : "a"(SYS_GETTIMEOFDAY), "D"(tv), "S"(tz));
    return retval;
}