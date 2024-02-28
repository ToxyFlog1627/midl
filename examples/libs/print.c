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

void print_num(int num) {
    char buffer[100];
    int i = 0, mask = 1;

    if (num < 0) {
        buffer[i++] = '-';
        num *= -1;
    }

    int num_copy = num;
    do {
        mask *= 10;
        num_copy /= 10;
    } while (num_copy > 0);
    mask /= 10;

    do {
        buffer[i++] = '0' + (num / mask) % 10;
        mask /= 10;
    } while (mask > 0);

    buffer[i] = '\n';
    buffer[i + 1] = '\0';

    print(buffer);
}