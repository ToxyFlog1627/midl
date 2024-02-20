#include "print.h"
#include "syscalls.h"
#include "types.h"

#define PRINT_NUM_BUF_SIZE 32

size_t strlen(const char *msg) {
    size_t len = 0;
    while (msg[len] != '\0') len++;
    return len;
}

int print(const char *msg) { return write(STDOUT, msg, strlen(msg)); }

int print_num(int64_t num) {
    char buffer[PRINT_NUM_BUF_SIZE];
    size_t i = 0, mask = 1;

    if (num < 0) {
        buffer[i++] = '-';
        num *= -1;
    }

    int64_t num_copy = num;
    do {
        mask *= 10;
        num_copy /= 10;
    } while (num_copy > 0);
    mask /= 10;

    do {
        buffer[i++] = '0' + (num / mask) % 10;
        mask /= 10;
    } while (mask > 0 && i < PRINT_NUM_BUF_SIZE);
    if (i + 1 >= PRINT_NUM_BUF_SIZE) return 1;

    buffer[i] = '\n';
    buffer[i + 1] = '\0';

    print(buffer);
    return 0;
}

int print_hex(uint64_t num) {
    char buffer[PRINT_NUM_BUF_SIZE];
    size_t i = 17;
    for (size_t j = 0; j <= i; j++) buffer[j] = '0';
    buffer[1] = 'x';
    buffer[i + 1] = '\n';
    buffer[i + 2] = '\0';

    while (num > 0) {
        uint8_t digit = num % 0x10;
        buffer[i--] = digit > 9 ? ('A' + digit - 10) : ('0' + digit);

        num >>= 4;
        if (i == 0) return 1;
    }

    print(buffer);
    return 0;
}
