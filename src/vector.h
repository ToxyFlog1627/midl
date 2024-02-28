#ifndef VECTOR_H
#define VECTOR_H

#include "types.h"

#define DEF_VECTOR_T(type, name)                                                                                       \
    typedef struct {                                                                                                   \
        size_t capacity;                                                                                               \
        size_t length;                                                                                                 \
        type *elements;                                                                                                \
    } name

DEF_VECTOR_T(size_t, v_size_t);
DEF_VECTOR_T(char *, v_str);

#define INITIAL_VECTOR_CAPACITY 16

#define VECTOR_PUSH(vector, element)                                                                                   \
    do {                                                                                                               \
        if (vector.capacity == 0) {                                                                                    \
            vector.capacity = INITIAL_VECTOR_CAPACITY;                                                                 \
            vector.length = 0;                                                                                         \
            vector.elements = malloc(vector.capacity * sizeof(*vector.elements));                                      \
        } else if (vector.length == vector.capacity) {                                                                 \
            vector.capacity *= 2;                                                                                      \
            vector.elements = realloc(vector.elements, vector.capacity * sizeof(*vector.elements));                    \
        }                                                                                                              \
                                                                                                                       \
        vector.elements[vector.length++] = element;                                                                    \
    } while (0);

#define VECTOR_FREE(vector)                                                                                            \
    do {                                                                                                               \
        vector.capacity = 0;                                                                                           \
        vector.length = 0;                                                                                             \
        free(vector.elements);                                                                                         \
        vector.elements = NULL;                                                                                        \
    } while (0);

#endif  // VECTOR_H