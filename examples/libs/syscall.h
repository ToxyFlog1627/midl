#ifndef _SYSCALL_H_
#define _SYSCALL_H_

#define STDOUT 2

extern int write(int fd, const void *buf, int len);

#endif  // _SYSCALL_H_