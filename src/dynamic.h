#ifndef DYNAMIC_H
#define DYNAMIC_H

#include "elf.h"
#include "types.h"
#include "vector.h"

typedef struct {
    uint64_t *plt_got;
    char *string_table;
    ELFSymbol *symbol_table;
    ELFRela *relas;
    uint64_t rela_count;
    char *init;
    vec_cstr library_search_paths;
    vec_cstr needed_libraries;
    ELFRela *jump_relocs;
    uint64_t jump_relocs_count;
    GNUHashTable gnu_hash_table;
} Dynamic;

Dynamic get_dynamic(char *base, const ELFHeader *elf);

#endif  // DYNAMIC_H