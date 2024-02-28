#ifndef _SYSCALL_H_
#define _SYSCALL_H_

#define STDOUT   2

#define O_RDONLY 0

typedef struct {
    long int sec;
    long int usec;
} timeval;

typedef struct {
    int minuteswest;
    int dsttime;
} timezone;

extern int read(int fd, void *buf, int len);
extern int write(int fd, const void *buf, int len);
extern int open(const char *path, int mode);
extern int close(int fd);
extern int gettimeofday(timeval *tv, timezone *tz);

#endif  // _SYSCALL_H_