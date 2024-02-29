#ifndef DYN_H
#define DYN_H

#include "elf.h"
#include "types.h"
#include "vector.h"

typedef struct {
    uint64_t *plt_got;
    char *string_table;
    Symbol *symbol_table;
    vec_cstr lib_search_paths;
    vec_cstr needed_libs;
    Rela *jump_relocs;
    GNUHashTable gnu_hash_table;
} DynamicInfo;

void get_dynamic_info(DynamicInfo *info, char *base, const ELFHeader *elf);

#endif  // DYN_H