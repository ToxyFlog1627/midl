#ifndef PRINT_H
#define PRINT_H

#include "types.h"

#define STDIN  0
#define STDOUT 1
#define STDERR 2

size_t strlen(const char *msg);

int print(const char *msg);
int print_num(int64_t num);
int print_hex(uint64_t num);

#endif  // PRINT_H