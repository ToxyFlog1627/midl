#include "dynamic.h"
#include "elf.h"
#include "types.h"
#include "ulibc.h"

Dynamic get_dynamic(char *base, const ELFHeader *elf) {
    Dynamic dynamic;
    memset(&dynamic, 0, sizeof(Dynamic));

    ELFSegment *dynamic_segment = NULL;
    for (ELFSegment *segment = (ELFSegment *) (base + elf->segments_offset); segment->type != SG_NULL; segment++) {
        if (segment->type == SG_DYNAMIC) {
            dynamic_segment = segment;
            break;
        }
    }
    assert(dynamic_segment != NULL, "Unable to find DYNAMIC segment.");

    vec_size_t needed_library_name_indexes;
    memset(&needed_library_name_indexes, 0, sizeof(vec_size_t));

    size_t library_search_paths_index = 0;
    void_fun_t **init_array = NULL, **fini_array = NULL;
    size_t init_array_size = 0, fini_array_size = 0;
    for (ELFDynamic *dyn = (ELFDynamic *) (base + dynamic_segment->memory_offset); dyn->type != DN_NULL; dyn++) {
        char *ptr = base + dyn->value;
        switch (dyn->type) {
            case DN_NEEDED:
                VECTOR_PUSH(needed_library_name_indexes, dyn->value);
                break;
            case DN_PLT_REL_SIZE:
                dynamic.jump_relocs_count = dyn->value / sizeof(ELFRela);
                break;
            case DN_PLT_GOT:
                dynamic.plt_got = (uint64_t *) ptr;
                break;
            case DN_HASH:
                UNIMPLEMENTED("DN_HASH");
                break;
            case DN_STRING_TABLE:
                dynamic.string_table = ptr;
                break;
            case DN_SYMBOL_TABLE:
                dynamic.symbol_table = (ELFSymbol *) ptr;
                break;
            case DN_RELA:
                dynamic.relas = (ELFRela *) ptr;
                break;
            case DN_RELA_SIZE:
                dynamic.rela_count = dyn->value / sizeof(ELFRela);
                break;
            case DN_RELA_ENTRY_SIZE:
                assert(dyn->value == sizeof(ELFRela),
                       "ERROR: Size mismatch between struct Rela and DN_RELA_ENTRY_SIZE.");
                break;
            case DN_STRING_TABLE_SIZE:
                break;
            case DN_SYMBOL_ENTRY_SIZE:
                assert(dyn->value == sizeof(ELFSymbol),
                       "ERROR: Size mismatch between struct Symbol and DN_SYMBOL_ENTRY_SIZE.");
                break;
            case DN_INIT: {
                void_fun_t *init;
                FUN_PTR_CAST(init) = ptr;
                VECTOR_PUSH(dynamic.init_array, init);
            } break;
            case DN_FINI: {
                void_fun_t *fini;
                FUN_PTR_CAST(fini) = ptr;
                VECTOR_PUSH(dynamic.fini_array, fini);
            } break;
            case DN_SO_NAME:
                break;
            case DN_RUNTIME_PATH:
                library_search_paths_index = dyn->value;
                break;
            case DN_SYMBOLIC:
                UNIMPLEMENTED("DN_SYMBOLIC");
                break;
            case DN_REL:
                UNIMPLEMENTED("DN_REL");
                break;
            case DN_REL_SIZE:
                UNIMPLEMENTED("DN_REL_SIZE");
                break;
            case DN_REL_ENTRY_SIZE:
                UNIMPLEMENTED("DN_REL_ENTRY_SIZE");
                break;
            case DN_PLT_REL_TYPE:
                break;
            case DN_DEBUG:
                break;
            case DN_TEXT_REL:
                UNIMPLEMENTED("DN_TEXT_REL");
                break;
            case DN_JUMP_RELOCS:
                dynamic.jump_relocs = (ELFRela *) ptr;
                break;
            case DN_BIND_NOW:
                UNIMPLEMENTED("DN_BIND_NOW");
                break;
            case DN_INIT_ARRAY:
                FUN_PTR_CAST(init_array) = ptr;
                break;
            case DN_FINI_ARRAY:
                FUN_PTR_CAST(fini_array) = ptr;
                break;
            case DN_INIT_ARRAY_SIZE:
                init_array_size = dyn->value;
                break;
            case DN_FINI_ARRAY_SIZE:
                fini_array_size = dyn->value;
                break;
            case DN_LIBRARY_SEARCH_PATHS:
                library_search_paths_index = dyn->value;
                break;
            case DN_FLAGS:
                print("INFO: ignoring DN_FLAGS\n");
                break;
            case DN_ENCODING:
                UNIMPLEMENTED("DN_ENCODING");
                break;
            case DN_PREINIT_ARRAY:
                UNIMPLEMENTED("DN_PREINIT_ARRAY");
                break;
            case DN_PREINIT_ARRAY_SIZE:
                UNIMPLEMENTED("DN_PREINIT_ARRAY_SIZE");
                break;
            case DN_SYMTAB_SHARED_IDX:
                UNIMPLEMENTED("DN_SYMTAB_SHARED_IDX");
                break;
            case DN_RELR_SIZE:
                dynamic.relr_count = dyn->value / sizeof(uint64_t);
                break;
            case DN_RELR:
                dynamic.relrs = (uint64_t *) ptr;
                break;
            case DN_RELR_ENTRY_SIZE:
                assert(dyn->value == sizeof(uint64_t), "ERROR: Size mismatch in RELR.");
                break;
            case DN_GNU_HASH: {
                GNUHashTable hash_table = *((GNUHashTable *) ptr);  // inits first 4 uint32_t fields
                hash_table.bloom_filter = (uint64_t *) (ptr + 4 * sizeof(uint32_t));
                hash_table.buckets = (uint32_t *) (hash_table.bloom_filter + hash_table.bloom_size);
                hash_table.chains = hash_table.buckets + hash_table.buckets_num;
                dynamic.gnu_hash_table = hash_table;
            } break;
            case DN_FLAGS_1:
                print("INFO: ignoring DN_FLAGS_1\n");
                break;
            case DN_VERSYM:
                print("INFO: ignoring DN_VERSYM\n");
                break;
            case DN_VERDEF:
                print("INFO: ignoring DN_VERDEF\n");
                break;
            case DN_VERDEFNUM:
                print("INFO: ignoring DN_VERDEFNUM\n");
                break;
            case DN_VERNEED:
                print("INFO: ignoring DN_VERNEED\n");
                break;
            case DN_VERNEEDNUM:
                print("INFO: ignoring DN_VERNEEDNUM\n");
                break;
            default:
                print("WARNING: Dynamic entry of unkown type.\n");
                break;
        }
    }

    assert(dynamic.string_table != NULL, "Unable to find STRING_TABLE.");
    assert(dynamic.symbol_table != NULL, "Unable to find SYMBOL_TABLE.");
    assert(dynamic.gnu_hash_table.buckets != NULL, "Unable to find HASH_TABLE(GNU_HASH_TABLE).");

    if (library_search_paths_index) {
        const char *ptr = dynamic.string_table + library_search_paths_index;
        while (*ptr) {
            const char *path_begin = ptr;
            while (*ptr && *ptr != ':') ptr++;

            size_t path_length = ptr - path_begin;
            char *path = (char *) malloc(path_length + 1);
            memcpy(path, path_begin, path_length);
            path[path_length] = '\0';
            VECTOR_PUSH(dynamic.library_search_paths, path);

            if (*ptr == ':') ptr++;
        }
    }

    for (size_t i = 0; i < needed_library_name_indexes.length; i++) {
        VECTOR_PUSH(dynamic.needed_libraries, dynamic.string_table + needed_library_name_indexes.data[i]);
    }
    VECTOR_FREE(needed_library_name_indexes);

    for (size_t i = 0; i < init_array_size; i++) VECTOR_PUSH(dynamic.init_array, init_array[i]);
    for (size_t i = 0; i < fini_array_size; i++) VECTOR_PUSH(dynamic.fini_array, fini_array[i]);

    return dynamic;
}
