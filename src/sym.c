#include "sym.h"
#include "elf.h"
#include "lib.h"
#include "print.h"
#include "types.h"
#include "ulibc.h"

static uint32_t elf_gnu_hash(const char *s) {
    uint32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s) h = h * 33 + c;
    return h;
}

static bool elf_gnu_bloom_test(const GNUHashTable *h, uint32_t hash) {
    uint64_t word = h->bloom_filter[(hash / 64) % h->bloom_size];
    uint64_t mask = (((uint64_t) 1) << (hash % 64)) | (((uint64_t) 1) << ((hash >> h->bloom_shift) % 64));
    return (word & mask) == mask;
}

Symbol *find_symbol(const DynamicInfo *info, const char *symbol_name) {
    uint32_t hash = elf_gnu_hash(symbol_name);
    if (!elf_gnu_bloom_test(&info->gnu_hash_table, hash)) return NULL;

    uint32_t sym_idx = info->gnu_hash_table.buckets[hash % info->gnu_hash_table.buckets_num];
    if (sym_idx < info->gnu_hash_table.first_symbol_index) return NULL;

    Symbol *sym = NULL;
    while (1) {
        uint32_t chain_index = sym_idx - info->gnu_hash_table.first_symbol_index;
        uint32_t chain_hash = info->gnu_hash_table.chains[chain_index];

        if ((hash | 1) == (chain_hash | 1)) {
            sym = info->symbol_table + sym_idx;
            if (strcmp(symbol_name, info->string_table + sym->name_offset) == 0) return sym;
        }

        if (chain_hash & 1) break;  // end of chain
        sym_idx++;
    }

    return NULL;
}
