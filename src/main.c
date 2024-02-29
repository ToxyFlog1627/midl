#include "elf.h"
#include "print.h"
#include "syscalls.h"
#include "types.h"
#include "ulibc.h"
#include "vector.h"

#define MAX_PATH_LENGTH 4096

#define AT_NULL         0
#define AT_PHDR         3

typedef struct {
    int argc;
    char **argv;
    char **envp;
    word *auxv;
} Args;

typedef struct {
    uint64_t *plt_got;
    char *string_table;
    Symbol *symbol_table;
    vec_cstr lib_search_paths;
    vec_cstr needed_libs;
    Rela *jump_relocs;
    GNUHashTable gnu_hash_table;
} DynamicInfo;

typedef int main_t(int argc, char **argv, char **envp);

#define ALIGN(value, alignment) (value & ~(alignment - 1))

#define FUN_PTR_CAST(fun_ptr)   *((void **) &(fun_ptr))

static bool strings_are_equal(const char *s1, const char *s2) {
    while (*s1 && *s2 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return *s1 == '\0' && *s2 == '\0';
}

static Args get_args() {
    word ptr;
    __asm__ volatile("mov (%%rbp), %[ret]\n\t" : [ret] "=r"(ptr));
    ptr += sizeof(word);  // skip old call frame

    Args args;

    args.argc = *((size_t *) ptr);
    args.argv = ((char **) (ptr)) + 1;
    args.envp = args.argv + args.argc + 1;
    args.auxv = (word *) args.envp;
    while (*(args.auxv++)) continue;

    return args;
}

static char *get_prog_base(Args *args) {
    word *var = args->auxv;
    while (*var != AT_PHDR) {
        var += 2;
        assert(var != AT_NULL, "Error in get_prog_base: couldn't find variable of type AT_PHDR.");
    }

    Segment *phdr = (Segment *) (*(var + 1));
    return (char *) (((word) phdr) - phdr->file_offset);
}

static void check_elf_header(ELFHeader *header) {
    assert(header->identifier.v.magic == ELF_MAGIC, "Error parsing ELF header: invalid magic.");
    assert(header->identifier.v.class == ELF_64, "Error parsing ELF header: ELF is not 64-bit.");
    assert(header->identifier.v.encoding == ELF_LSB, "Error parsing ELF header: ELF is not LSB.");
    assert(header->identifier.v.version == ELF_VERSION, "Error parsing ELF header: ELF version mismatch.");
    assert(header->identifier.v.abi == ELF_SYSV_ABI, "Error parsing ELF header: ABI type mismatch.");
    assert(header->identifier.v.abi_version == ELF_ABI_VERSION, "Error parsing ELF header: ABI version mismatch.");
    assert(header->type == ELF_EXEC_DYNAMIC, "Error parsing ELF header: ELF is not of type DYN.");
    assert(header->arch == ELF_AMD64, "Error parsing ELF header: CPU must be AMD64(x86_64).");
    assert(header->version == ELF_VERSION, "Error parsing ELF header: ELF version mismatch.");
    assert(header->segment_entry_size == sizeof(Segment), "Error parsing ELF header: segment size mismatch!");
}

static void get_dynamic_info(DynamicInfo *info, char *base, const ELFHeader *elf) {
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

static void create_path(char *buffer, const char *path, const char *filename) {
    size_t path_length = strlen(path), filename_length = strlen(filename);

    memcpy(buffer, path, path_length);
    buffer[path_length++] = '/';

    memcpy(buffer + path_length, filename, filename_length);
    buffer[path_length + filename_length] = '\0';
}

static int open_library(const vec_cstr *library_search_paths, const char *library_name) {
    static char library_path[MAX_PATH_LENGTH];

    for (size_t i = 0; i < library_search_paths->length; i++) {
        create_path(library_path, library_search_paths->elements[i], library_name);
        int fd = open(library_path, O_RDWR, NULL);
        if (fd >= 0) return fd;
    }

    print("Error loading shared library: unable to find library \"");
    print(library_name);
    print("\".\n");
    exit(1);
}

typedef struct {
    uint64_t memory_offset;
    uint64_t file_size;
    uint64_t flags;
    uint64_t file_offset;
} LoadSegment;

DEF_VECTOR_T(LoadSegment, load_seg_vec);

static char *load_library(const ELFHeader *lib_elf, int fd) {
    // TODO: loading multiple libraries doesn't work properly due to initial memory_size calculation
    // not taking alignment into account!

    load_seg_vec load_segs;
    memset(&load_segs, 0, sizeof(load_seg_vec));

    // TODO: instead of this vector bullshit, simply read an array of segments into malloced memory
    // change them there and then read again?

    size_t memory_size = 0;
    lseek(fd, lib_elf->segments_offset, SEEK_SET);
    for (size_t i = 0; i < lib_elf->segment_entry_num; i++) {
        Segment seg;
        read(fd, &seg, sizeof(seg));

        if (seg.type != SG_LOAD) continue;
        assert(seg.memory_size == seg.file_size, "Segments with mem_size != file_size are unimplemented.");

        if (seg.memory_offset % seg.alignment != 0) {
            assert(seg.file_offset % seg.alignment == seg.memory_offset % seg.alignment,
                   "Memory and file offsets must be equally misaligned.");

            uint64_t aligned_file_offset = ALIGN(seg.file_offset, seg.alignment);
            uint64_t aligned_memory_offset = ALIGN(seg.memory_offset, seg.alignment);

            seg.file_size += seg.file_offset - aligned_file_offset + seg.file_size;
            seg.file_offset = aligned_file_offset;
            seg.memory_offset = aligned_memory_offset;
        }

        size_t new_size = seg.memory_offset + seg.file_size;
        if (new_size > memory_size) memory_size = new_size;

        LoadSegment load_seg = {seg.memory_offset, seg.file_size, seg.flags, seg.file_offset};
        VECTOR_PUSH(load_segs, load_seg);
    }

    // memory of this mmap is not used, because the purpose of this call is to locate
    // contiguous chunk of address space which later gets overriden with library data
    char *lib_base = mmap(NULL, memory_size, MAP_PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, NULL, NULL);
    if (((int64_t) lib_base) < 0) {
        print("Anonymous mmap failed: unable to allocate memory for a shared library.");
        exit(1);
    }

    uint64_t prev_mmap_end = 0;
    lseek(fd, lib_elf->segments_offset, SEEK_SET);
    for (size_t i = 0; i < load_segs.length; i++) {
        LoadSegment seg = load_segs.elements[i];

        assert(seg.memory_offset >= prev_mmap_end, "Mmaped segments overlap.");
        void *result = mmap(lib_base + seg.memory_offset, seg.file_size, seg.flags, MAP_PRIVATE | MAP_FIXED, fd,
                            seg.file_offset);
        if (((int64_t) result) < 0) {
            print("mmap failed: unable to load shared library.");
            exit(1);
        }
        prev_mmap_end = seg.memory_offset + seg.file_size;
    }

    VECTOR_FREE(load_segs);
    return lib_base;
}

static Symbol *find_symbol(const DynamicInfo *info, const char *symbol_name) {
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
            if (strings_are_equal(symbol_name, info->string_table + sym->name_offset)) return sym;
        }

        if (chain_hash & 1) break;  // end of chain
        sym_idx++;
    }

    return NULL;
}

typedef struct {
    const char *name;
    char *base;
    DynamicInfo dyn_info;
} LibInfo;

DEF_VECTOR_T(LibInfo, vec_libs);

static vec_libs libs;  // TODO: use pointers?

// TODO: move + rename ^

static void resolve_symbols(char *base, const DynamicInfo *info) {
    for (size_t i = 0; i < info->needed_libs.length; i++) {
        LibInfo lib_info;
        lib_info.name = info->needed_libs.elements[i];

        bool found = false;
        for (size_t j = 0; j < libs.length; j++) {
            if (strings_are_equal(libs.elements[j].name, lib_info.name)) {
                found = true;
                break;
            }
        }
        if (found) break;

        int fd = open_library(&info->lib_search_paths, lib_info.name);

        ELFHeader lib_elf;
        read(fd, &lib_elf, sizeof(lib_elf));  // TODO: do we even have to open it to begin with?
        check_elf_header(&lib_elf);

        lib_info.base = load_library(&lib_elf, fd);
        close(fd);

        get_dynamic_info(&lib_info.dyn_info, lib_info.base, &lib_elf);

        VECTOR_PUSH(libs, lib_info);

        resolve_symbols(lib_info.base, &lib_info.dyn_info);

        // TODO: init
    }

    if (!info->jump_relocs) return;
    for (Rela *rela = info->jump_relocs; rela->offset != NULL; rela++) {
        assert(rela->addend == 0, "Error initializing PLT: REL_JUMP_SLOT doesn't use addend.");
        assert(rela->info.v.type == RL_JUMP_SLOT,
               "Error initializing PLT entries: relocation type must be REL_JUMP_SLOT.");

        Symbol *sym = info->symbol_table + rela->info.v.symbol_index;
        assert(sym->binding == SMB_GLOBAL || sym->binding == SMB_WEAK,
               "Error initializing PLT: relocated symbol must have GLOBAL or WEAK binding.");
        assert(sym->type == SMT_FUNC, "Error initializing PLT: relocated symbol must be of type FUNC.");
        assert(sym->visibility == SMV_DEFAULT,
               "Error initializing PLT: relocated symbol must have DEFAULT visibility.");

        const char *rel_symbol_name = info->string_table + sym->name_offset;

        Symbol *csym = find_symbol(info, rel_symbol_name);
        if (csym) {
            *((uint64_t *) (base + rela->offset)) = (uint64_t) (base + csym->value);
            continue;
        }

        bool found = false;
        for (size_t j = 0; j < libs.length; j++) {
            LibInfo lib_info = libs.elements[j];

            Symbol *csym = find_symbol(&lib_info.dyn_info, rel_symbol_name);

            if (csym) {
                *((uint64_t *) (base + rela->offset)) = (uint64_t) (lib_info.base + csym->value);
                found = true;
                break;
            }
        }
        assert(found, "UNIMPLEMENTED");
    }

    // TODO: link itself
}

void entry() {
    Args args = get_args();
    char *prog_base = get_prog_base(&args);
    ELFHeader *prog_elf = (ELFHeader *) prog_base;
    check_elf_header(prog_elf);

    DynamicInfo prog_info;
    get_dynamic_info(&prog_info, prog_base, prog_elf);

    resolve_symbols(prog_base, &prog_info);

    main_t *main;
    FUN_PTR_CAST(main) = prog_base + prog_elf->entry;
    int exit_code = main(args.argc, args.argv, args.envp);

    exit(exit_code);
}

// TODO: for .so dynamic linker, change type, add README, etc.
// extern Elf32_Dyn _DYNAMIC[];
// extern Elf32_Addr _GLOBAL_OFFSET_TABLE_[];