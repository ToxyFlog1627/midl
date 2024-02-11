#include "print.h"
#include "syscall.h"

#define STDOUT_FD 1

typedef unsigned long size_t;

size_t strlen(const char *msg) {
    size_t len = 0;
    while (msg[len] != '\0') len++;
    return len;
}

void print(const char *msg) {
    size_t msg_len = strlen(msg);
    write(STDOUT, msg, msg_len);
}