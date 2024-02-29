#include "dyn.h"
#include "elf.h"
#include "print.h"
#include "types.h"
#include "ulibc.h"

void get_dynamic_info(DynamicInfo *info, char *base, const ELFHeader *elf) {
    memset(info, 0, sizeof(DynamicInfo));

    Segment *segment = NULL;
    for (Segment *s = (Segment *) (base + elf->segments_offset); s->type != SG_NULL; s++) {
        if (s->type == SG_DYNAMIC) {
            segment = s;
            break;
        }
    }
    assert(segment != NULL, "Unable to find DYNAMIC segment.");

    vec_size_t needed_lib_name_idxs;
    memset(&needed_lib_name_idxs, 0, sizeof(vec_size_t));

    size_t lib_search_paths_idx = 0;
    for (Dynamic *dyn = (Dynamic *) (base + segment->memory_offset); dyn->type != DN_NULL; dyn++) {
        char *ptr = base + dyn->value;
        switch (dyn->type) {
            case DN_NEEDED:
                VECTOR_PUSH(needed_lib_name_idxs, dyn->value);
                break;
            case DN_PLT_SIZE:
                break;
            case DN_PLT_GOT:
                info->plt_got = (uint64_t *) ptr;
                break;
            case DN_HASH:
                assert(false, "DN_HASH UNIMPLEMENTED");
                break;
            case DN_STRING_TABLE:
                info->string_table = ptr;
                break;
            case DN_SYMBOL_TABLE:
                info->symbol_table = (Symbol *) ptr;
                break;
            case DN_RELA:
                assert(false, "DN_RELA UNIMPLEMENTED");
                break;
            case DN_RELA_SIZE:
                break;
            case DN_RELA_ENTRY_SIZE:
                assert(dyn->value == sizeof(Rela), "Size mismatch between struct Rela and DN_RELA_ENTRY_SIZE.");
                break;
            case DN_STRING_TABLE_SIZE:
                break;
            case DN_SYMBOL_ENTRY_SIZE:
                assert(dyn->value == sizeof(Symbol), "Size mismatch between struct Symbol and DN_SYMBOL_ENTRY_SIZE.");
                break;
            case DN_INIT:
                assert(false, "DN_INIT UNIMPLEMENTED");
                break;
            case DN_FINI:
                assert(false, "DN_FINI UNIMPLEMENTED");
                break;
            case DN_SO_NAME:
                assert(false, "DN_SO_NAME UNIMPLEMENTED");
                break;
            case DN_RUNTIME_PATH:
                lib_search_paths_idx = dyn->value;
                break;
            case DN_SYMBOLIC:
                assert(false, "DN_SYMBOLIC UNIMPLEMENTED");
                break;
            case DN_REL:
                assert(false, "DN_REL UNIMPLEMENTED");
                break;
            case DN_REL_SIZE:
                assert(false, "DN_REL_SIZE UNIMPLEMENTED");
                break;
            case DN_REL_ENTRY_SIZE:
                assert(false, "DN_REL_ENTRY_SIZE UNIMPLEMENTED");
                break;
            case DN_PLT_REL_TYPE:
                assert(dyn->value == RL_JUMP_SLOT,
                       "UNIMPLEMENTED: the only supported relocation type is REL_JUMP_SLOT.");
                break;
            case DN_DEBUG:
                break;
            case DN_TEXT_REL:
                assert(false, "DN_TEXT_REL UNIMPLEMENTED");
                break;
            case DN_JUMP_RELOCS:
                info->jump_relocs = (Rela *) ptr;
                break;
            case DN_BIND_NOW:
                assert(false, "DN_BIND_NOW UNIMPLEMENTED");
                break;
            case DN_INIT_ARRAY:
                assert(false, "DN_INIT_ARRAY UNIMPLEMENTED");
                break;
            case DN_FINI_ARRAY:
                assert(false, "DN_FINI_ARRAY UNIMPLEMENTED");
                break;
            case DN_INIT_ARRAY_SIZE:
                assert(false, "DN_INIT_ARRAY_SIZE UNIMPLEMENTED");
                break;
            case DN_FINI_ARRAY_SIZE:
                assert(false, "DN_FINI_ARRAY_SIZE UNIMPLEMENTED");
                break;
            case DN_LIBRARY_SEARCH_PATHS:
                lib_search_paths_idx = dyn->value;
                break;
            case DN_FLAGS:
                assert(false, "DN_FLAGS UNIMPLEMENTED");
                break;
            case DN_ENCODING:
                assert(false, "DN_ENCODING UNIMPLEMENTED");
                break;
            case DN_PREINIT_ARRAY:
                assert(false, "DN_PREINIT_ARRAY UNIMPLEMENTED");
                break;
            case DN_PREINIT_ARRAY_SIZE:
                assert(false, "DN_PREINIT_ARRAY_SIZE UNIMPLEMENTED");
                break;
            case DN_SYMTAB_SHARED_IDX:
                assert(false, "DN_SYMTAB_SHARED_IDX UNIMPLEMENTED");
                break;
            case DN_RELR_SIZE:
                assert(false, "DN_RELR_SIZE UNIMPLEMENTED");
                break;
            case DN_RELR:
                assert(false, "DN_RELR UNIMPLEMENTED");
                break;
            case DN_RELR_ENTRY_SIZE:
                assert(false, "DN_RELR_ENTRY_SIZE UNIMPLEMENTED");
                break;
            case DN_GNU_HASH: {
                GNUHashTable hash_table = *((GNUHashTable *) ptr);  // inits first 4 uint32_t fields
                hash_table.bloom_filter = (uint64_t *) (ptr + 4 * sizeof(uint32_t));
                hash_table.buckets = (uint32_t *) (hash_table.bloom_filter + hash_table.bloom_size);
                hash_table.chains = hash_table.buckets + hash_table.buckets_num;
                info->gnu_hash_table = hash_table;
            } break;
            case DN_FLAGS_1:
                break;
            default:
                print("WARNING: Dynamic entry of unkown type.\n");  // TODO: print type
                break;
        }
    }

    assert(info->string_table != NULL, "Unable to find string table.");
    assert(info->symbol_table != NULL, "Unable to find symbol table.");
    assert(info->gnu_hash_table.buckets != NULL, "Unable to find hash table.");

    if (lib_search_paths_idx) {
        const char *p = info->string_table + lib_search_paths_idx;
        while (*p) {
            const char *path_begin = p;
            while (*p && *p != ':') p++;

            size_t path_length = p - path_begin;
            char *path = (char *) malloc(path_length + 1);
            memcpy(path, path_begin, path_length);
            path[path_length] = '\0';
            VECTOR_PUSH(info->lib_search_paths, path);

            if (*p == ':') p++;
        }
    }

    for (size_t i = 0; i < needed_lib_name_idxs.length; i++) {
        size_t idx = needed_lib_name_idxs.elements[i];
        VECTOR_PUSH(info->needed_libs, info->string_table + idx);
    }
    VECTOR_FREE(needed_lib_name_idxs);
}
