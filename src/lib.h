#ifndef LIB_H
#define LIB_H

#include "dyn.h"
#include "vector.h"

typedef struct {
    const char *name;
    char *base;
    DynamicInfo dyn_info;
} LibInfo;

DEF_VECTOR_T(LibInfo, vec_lib_info);

void load_library(LibInfo *lib_info, const vec_cstr *lib_search_paths, const char *library_name);

#endif  // LIB_H