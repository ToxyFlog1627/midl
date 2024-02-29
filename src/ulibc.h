// Micro subset of libc needed by the linker

#ifndef ULIBC_H
#define ULIBC_H

#include "types.h"

#define NULL   0

#define STDIN  0
#define STDOUT 1
#define STDERR 2

#define UNIMPLEMENTED(message)                                                                                         \
    do {                                                                                                               \
        print(message);                                                                                                \
        print(" is unimplemented at ");                                                                                \
        print(__FILE__);                                                                                               \
        print(":");                                                                                                    \
        print_num(__LINE__);                                                                                           \
        exit(1);                                                                                                       \
    } while (0)

__attribute__((noreturn)) void exit(int exit_code);

void assert(bool condition, const char *error_message);

int print(const char *message);
int print_num(int64_t num);
int print_hex(uint64_t num);

size_t strlen(const char *msg);
int strcmp(const char *s1, const char *s2);
char *strdup(const char *s);

void memcpy(void *dest, const void *src, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
void memset(void *s, char c, size_t n);

void *malloc(size_t n);
void free(void *ptr);
void *realloc(void *ptr, size_t n);

#endif  // ULIBC_H