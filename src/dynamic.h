#ifndef DYNAMIC_H
#define DYNAMIC_H

#include "elf.h"
#include "types.h"
#include "vector.h"

DEF_VECTOR_T(void_fun_t *, vec_void_fun);

typedef struct {
    uint64_t *plt_got;
    char *string_table;
    ELFSymbol *symbol_table;
    GNUHashTable gnu_hash_table;
    vec_cstr needed_libraries;
    vec_cstr library_search_paths;
    ELFRela *relas;
    uint64_t rela_count;
    uint64_t *relrs;
    uint64_t relr_count;
    ELFRela *jump_relocs;
    uint64_t jump_relocs_count;
    vec_void_fun init_array;
    vec_void_fun fini_array;
} Dynamic;

Dynamic get_dynamic(char *base, const ELFHeader *elf);

#endif  // DYNAMIC_H