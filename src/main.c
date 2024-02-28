#include "elf.h"
#include "print.h"
#include "syscalls.h"
#include "types.h"
#include "ulibc.h"

#define AT_NULL 0
#define AT_PHDR 3

typedef struct {
    int argc;
    char **argv;
    char **envp;
    word *auxv;
} Args;

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

static void link(char *prog_base, ELFHeader *prog_elf) {
#define PATH_SIZE 1024
#define LIB_SIZE  256

    Segment *dynamic_segment = NULL;
    for (Segment *seg = (Segment *) (prog_base + prog_elf->segments_offset); seg->type != SG_NULL; seg++) {
        if (seg->type == SG_DYNAMIC) {
            dynamic_segment = seg;
            break;
        }
    }
    assert(dynamic_segment != NULL, "Error parsing ELF header: no dynamic segment");

    uint64_t lib_name_idx[LIB_SIZE];  // TODO: dynamic array
    size_t li = 0;
    uint64_t *plt_got = NULL;
    char *string_table = NULL;
    uint64_t lib_search_paths_idx = NULL;
    Relocation *relocations = NULL;
    Symbol *symbol_table = NULL;
    for (Dynamic *dyn = (Dynamic *) (prog_base + dynamic_segment->memory_offset); dyn->type != DN_NULL; dyn++) {
        // TODO: switch?
        if (dyn->type == DN_PLT_GOT) {
            plt_got = (uint64_t *) (prog_base + dyn->value);
        } else if (dyn->type == DN_NEEDED) {
            assert(li <= LIB_SIZE, "Too many shared libraries!");
            lib_name_idx[li++] = dyn->value;
        } else if (dyn->type == DN_STRING_TABLE) {
            assert(string_table == NULL, "UNIMPLEMENTED");
            string_table = prog_base + dyn->value;
        } else if (dyn->type == DN_LIBRARY_SEARCH_PATHS) {
            assert(lib_search_paths_idx == NULL, "UNIMPLEMENTED");
            lib_search_paths_idx = dyn->value;
        } else if (dyn->type == DN_RELA || dyn->type == DN_REL || dyn->type == DN_RELR) {
            assert(false, "UNIMPLEMENTED: the only supported relocation type is REL_JUMP_SLOT.");
        } else if (dyn->type == DN_PLT_REL_TYPE) {
            assert(dyn->value == RL_JUMP_SLOT, "UNIMPLEMENTED: the only supported relocation type is REL_JUMP_SLOT.");
        } else if (dyn->type == DN_JUMP_RELOCS) {
            relocations = (Relocation *) (prog_base + dyn->value);
        } else if (dyn->type == DN_SYMBOL_TABLE) {
            symbol_table = (Symbol *) (prog_base + dyn->value);
        }
    }
    assert(plt_got != NULL, "Can't locate GOT.");
    assert(string_table != NULL, "Can't locate string table.");
    assert(lib_search_paths_idx != NULL, "Can't locate library search paths.");
    assert(relocations != NULL, "Can't locate REL_JUMP_SLOT.");
    assert(symbol_table != NULL, "Can't locate symbol table.");

    char *lib_search_paths = string_table + lib_search_paths_idx;
    char *p = lib_search_paths;
    while (*p) assert(*(p++) != ':', "UNIMPLEMENTED: multiple library search paths aren't implemented yet.");
    assert(lib_search_paths[0] == '/', "Library search paths must be absolute.");

    size_t lib_search_path_length = strlen(lib_search_paths);
    char lib_path[PATH_SIZE + 1];
    memcpy(lib_path, lib_search_paths, lib_search_path_length);
    lib_path[lib_search_path_length] = '/';
    lib_search_path_length++;
    for (size_t i = 0; i < li; i++) {
        char *library_name = string_table + lib_name_idx[i];
        size_t library_name_length = strlen(library_name);
        memcpy(lib_path + lib_search_path_length, library_name, library_name_length);
        lib_path[lib_search_path_length + library_name_length] = '\0';

        int fd = open(lib_path, O_RDWR, NULL);
        if (fd == ENOENT) {
            print("Error loading shared library: unable to find library \"");
            print(library_name);
            print("\" at \"");
            print(lib_search_paths);
            print("\".\n");
            exit(1);
        } else if (fd < 0) {
            print("Error loading shared library.");
            exit(1);
        }

        ELFHeader lib_elf;
        read(fd, &lib_elf, sizeof(lib_elf));
        check_elf_header(&lib_elf);

        uint64_t dynamic_offset = 0;
        size_t lib_elf_size = 0;
        lseek(fd, lib_elf.segments_offset, SEEK_SET);
        for (size_t i = 0; i < lib_elf.segment_entry_num; i++) {
            Segment seg;
            read(fd, &seg, sizeof(seg));

            if (seg.type == SG_LOAD) {
                size_t new_size = seg.memory_offset + seg.memory_size;
                if (new_size > lib_elf_size) lib_elf_size = new_size;
            } else if (seg.type == SG_DYNAMIC) {
                dynamic_offset = seg.memory_offset;
            }
        }
        assert(dynamic_offset > 0 && dynamic_offset < lib_elf_size, "Invalid offset of DYNAMIC segment.");

        // memory of this mmap is not used, because the purpose of this call is to locate
        // contiguous chunk of address space which later gets overriden with library data
        char *lib_base = mmap(NULL, lib_elf_size, MAP_PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, NULL, NULL);
        if (((int64_t) lib_base) < 0) {
            print("Anonymous mmap failed: unable to allocate memory for shared library.");
            exit(1);
        }

        uint64_t prev_mmap_end = 0;
        lseek(fd, lib_elf.segments_offset, SEEK_SET);
        for (size_t i = 0; i < lib_elf.segment_entry_num; i++) {
            Segment seg;
            read(fd, &seg, sizeof(seg));

            if (seg.type == SG_LOAD) {
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

                assert(seg.memory_offset >= prev_mmap_end, "Mmaped segments overlap.");
                void *result = mmap(lib_base + seg.memory_offset, seg.file_size, seg.flags, MAP_PRIVATE | MAP_FIXED, fd,
                                    seg.file_offset);
                if (((int64_t) result) < 0) {
                    print("mmap failed: unable to load shared library.");
                    exit(1);
                }
                prev_mmap_end = seg.memory_offset + seg.file_size;
            }
        }
        close(fd);

        Symbol *lib_symbol_table = NULL;
        char *lib_string_table = NULL;
        HashTable hash_table;  // NOTE: zero-initializing causes it to SEGFAULT ¯\_(ツ)_/¯
        for (Dynamic *dyn = (Dynamic *) (lib_base + dynamic_offset); dyn->type != DN_NULL; dyn++) {
            if (dyn->type == DN_NEEDED) assert(false, "chained_libs are unimplemented");
            else if (dyn->type == DN_HASH) {
                assert(false, "Non-GNU hash tables are not supported (yet?).");
            } else if (dyn->type == DN_GNU_HASH) {
                hash_table = *((HashTable *) (lib_base + dyn->value));  // inits first 4 uint32_t fields
                hash_table.bloom_filter = (uint64_t *) (lib_base + dyn->value + 4 * sizeof(uint32_t));
                hash_table.buckets = (uint32_t *) (hash_table.bloom_filter + hash_table.bloom_size);
                hash_table.chains = hash_table.buckets + hash_table.buckets_num;
            } else if (dyn->type == DN_SYMBOL_TABLE) {
                lib_symbol_table = (Symbol *) (lib_base + dyn->value);
            } else if (dyn->type == DN_STRING_TABLE) {
                lib_string_table = lib_base + dyn->value;
            }
        }
        // TODO: check hash_table
        assert(lib_symbol_table != NULL, "Error parsing library: couldn't find symbol table.");
        assert(lib_string_table != NULL, "Error parsing library: couldn't find string table.");

        for (Relocation *rel = relocations; rel->offset != NULL; rel++) {
            assert(rel->addend == 0, "Error initializingi PLT: REL_JUMP_SLOT doesn't use addend.");
            assert(rel->info.v.type == RL_JUMP_SLOT,
                   "Error initializing PLT entries: relocation type must be REL_JUMP_SLOT.");

            Symbol sym = symbol_table[rel->info.v.symbol_index];
            assert(sym.binding == SMB_GLOBAL || sym.binding == SMB_WEAK,
                   "Error initializing PLT: relocated symbol must have GLOBAL or WEAK binding.");
            assert(sym.type == SMT_FUNC, "Error initializing PLT: relocated symbol must be of type FUNC.");
            assert(sym.visibility == SMV_DEFAULT,
                   "Error initializing PLT: relocated symbol must have DEFAULT visibility.");

            const char *rel_symbol_name = string_table + sym.name_offset;

            // check with bloom filter
            uint32_t hash = elf_gnu_hash(rel_symbol_name);
            if (!elf_gnu_bloom_test(&hash_table, hash))
                assert(false, "UNIMPLEMENTED: handle symbols not found in bloom filter");

            // get symbol index
            uint32_t sym_idx = hash_table.buckets[hash % hash_table.buckets_num];
            if (sym_idx < hash_table.first_symbol_index)
                assert(false, "UNIMPLEMENTED: handle symbols not found in hash table buckets");

            // look for entry with matching hash in hash chains
            Symbol *cur_sym = NULL;
            while (1) {
                uint32_t chain_index = sym_idx - hash_table.first_symbol_index;
                uint32_t chain_hash = hash_table.chains[chain_index];

                if ((hash | 1) == (chain_hash | 1)) {
                    cur_sym = lib_symbol_table + sym_idx;
                    if (strings_are_equal(rel_symbol_name, lib_string_table + cur_sym->name_offset)) break;
                    cur_sym = NULL;
                }

                if (chain_hash & 1) break;  // end of chain
                sym_idx++;
            }
            if (cur_sym == NULL) assert(false, "UNIMPLEMENTED: handle symbols not found in hash table chains");

            // relocate it
            *((uint64_t *) (prog_base + rel->offset)) = (uint64_t) (lib_base + cur_sym->value);
        }
    }
#undef LIB_SIZE
#undef PATH_SIZE
}

void entry() {
    Args args = get_args();
    char *prog_base = get_prog_base(&args);

    ELFHeader *prog_elf = (ELFHeader *) prog_base;
    check_elf_header(prog_elf);

    link(prog_base, prog_elf);

    main_t *main;
    FUN_PTR_CAST(main) = prog_base + prog_elf->entry;
    int exit_code = main(args.argc, args.argv, args.envp);

    exit(exit_code);
}