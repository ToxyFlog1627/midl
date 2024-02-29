#ifndef TYPES_H
#define TYPES_H

typedef long word;

typedef unsigned long size_t;
typedef unsigned long off_t;

typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int int16_t;
typedef short unsigned int uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long int int64_t;
typedef long unsigned int uint64_t;

typedef char bool;
#define false 0
#define true  1

typedef void void_fun_t(void);
#define FUN_PTR_CAST(fun_ptr) *((void **) &(fun_ptr))

#endif  // TYPES_H