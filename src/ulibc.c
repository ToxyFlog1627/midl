#include "ulibc.h"
#include "print.h"
#include "syscalls.h"
#include "types.h"

__attribute__((noreturn)) void exit(int exit_code) {
    _exit(exit_code);
    __builtin_unreachable();
}

void assert(bool condition, const char *error_msg) {
    if (!condition) {
        print(error_msg);
        if (error_msg[strlen(error_msg) - 1] != '\n') print("\n");
        exit(1);
    }
}

// TODO: use libc-impl or assembly instruction to speed up
void memcpy(void *dest, void *src, size_t n) {
    char *to = (char *) dest, *from = (char *) src;
    while (n--) *(to++) = *(from++);
}

// NOTE: this partial implementation always returns 1 if strings are different
int memcmp(void *s1, void *s2, size_t n) {
    if (n == 0) return 0;

    char *p1 = (char *) s1, *p2 = (char *) s2;
    while (*(p1++) == *(p2++) && --n > 0) continue;
    return n;
}
