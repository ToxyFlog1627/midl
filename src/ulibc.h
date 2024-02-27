#ifndef ULIBC_H
#define ULIBC_H

#include "types.h"

#define NULL 0

__attribute__((noreturn)) void exit(int exit_code);
void assert(bool condition, const char *error_msg);
void memcpy(void *dest, void *src, size_t n);
int memcmp(void *s1, void *s2, size_t n);

#endif  // ULIBC_H