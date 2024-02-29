#ifndef LIBRARY_H
#define LIBRARY_H

#include "dynamic.h"
#include "vector.h"

typedef struct {
    const char *name;
    char *base;
    Dynamic dynamic;
} Library;

DEF_VECTOR_T(Library, vec_libs);

Library load_library(const vec_cstr *lib_search_paths, const char *library_name);

#endif  // LIBRARY_H