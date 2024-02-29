#include "symbol.h"
#include "elf.h"
#include "library.h"
#include "types.h"
#include "ulibc.h"

static uint32_t elf_gnu_hash(const char *symbol_name) {
    uint32_t h = 5381;
    for (unsigned char c = *symbol_name; c != '\0'; c = *++symbol_name) h = h * 33 + c;
    return h;
}

static bool elf_gnu_bloom_test(const GNUHashTable *hash_table, uint32_t hash) {
    uint64_t word = hash_table->bloom_filter[(hash / 64) % hash_table->bloom_size];
    uint64_t mask = (((uint64_t) 1) << (hash % 64)) | (((uint64_t) 1) << ((hash >> hash_table->bloom_shift) % 64));
    return (word & mask) == mask;
}

ELFSymbol *find_symbol(const Dynamic *dynamic, const char *symbol_name) {
    uint32_t hash = elf_gnu_hash(symbol_name);
    if (!elf_gnu_bloom_test(&dynamic->gnu_hash_table, hash)) return NULL;

    uint32_t symbol_index = dynamic->gnu_hash_table.buckets[hash % dynamic->gnu_hash_table.buckets_num];
    if (symbol_index < dynamic->gnu_hash_table.first_symbol_index) return NULL;

    ELFSymbol *symbol = NULL;
    while (1) {
        uint32_t chain_index = symbol_index - dynamic->gnu_hash_table.first_symbol_index;
        uint32_t chain_hash = dynamic->gnu_hash_table.chains[chain_index];

        if ((hash | 1) == (chain_hash | 1)) {
            symbol = dynamic->symbol_table + symbol_index;
            if (strcmp(symbol_name, dynamic->string_table + symbol->name_offset) == 0) return symbol;
        }

        if (chain_hash & 1) break;  // end of chain
        symbol_index++;
    }

    return NULL;
}
