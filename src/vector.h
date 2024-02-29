// Simple macro-based dynamic array

#ifndef VECTOR_H
#define VECTOR_H

#include "types.h"

#define DEF_VECTOR_T(type, name)                                                                                       \
    typedef struct {                                                                                                   \
        size_t capacity;                                                                                               \
        size_t length;                                                                                                 \
        type *data;                                                                                                    \
    } name

DEF_VECTOR_T(size_t, vec_size_t);
DEF_VECTOR_T(char *, vec_cstr);

#define INITIAL_VECTOR_CAPACITY 16

#define VECTOR_PUSH(vector, element)                                                                                   \
    do {                                                                                                               \
        if (vector.capacity == 0) {                                                                                    \
            vector.capacity = INITIAL_VECTOR_CAPACITY;                                                                 \
            vector.length = 0;                                                                                         \
            vector.data = malloc(vector.capacity * sizeof(*vector.data));                                              \
        } else if (vector.length == vector.capacity) {                                                                 \
            vector.capacity *= 2;                                                                                      \
            vector.data = realloc(vector.data, vector.capacity * sizeof(*vector.data));                                \
        }                                                                                                              \
                                                                                                                       \
        vector.data[vector.length++] = element;                                                                        \
    } while (0);

#define VECTOR_FREE(vector)                                                                                            \
    do {                                                                                                               \
        vector.capacity = 0;                                                                                           \
        vector.length = 0;                                                                                             \
        if (vector.data) free(vector.data);                                                                            \
        vector.data = NULL;                                                                                            \
    } while (0);

#endif  // VECTOR_H