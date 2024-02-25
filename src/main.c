#include "elf.h"
#include "print.h"
#include "syscalls.h"
#include "types.h"

#define NULL 0

// auxillary variable types
#define AT_NULL 0
#define AT_PHDR 3
#define AT_BASE 7

typedef struct {
    int argc;
    char **argv;
    char **envp;
    word *auxv;
} Args;

typedef int main_t(int argc, char **argv, char **envp);

Args get_args() {
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

void assert(bool condition, const char *error_msg) {
    if (!condition) {
        print(error_msg);
        if (error_msg[strlen(error_msg) - 1] != '\n') print("\n");
        exit(1);
    }
}

void assert_supported_elf(ELFHeader *header) {
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
    assert(header->section_entry_size == sizeof(Section), "Error parsing ELF header: section size mismatch!");
}

char *get_prog_base(Args *args) {
    word *var = args->auxv;
    while (*var != AT_PHDR) {
        var += 2;
        assert(var != NULL, "Error parsing auxillary variables: expected AT_PHDR.");
    }

    Segment *phdr = (Segment *) (*(var + 1));
    return (char *) (((word) phdr) - phdr->offset);
}

Segment *get_segment(char *prog_base, ELFHeader *elf, uint32_t type) {
    assert(type < _SG_SIZE, "Error in get_segment: expected type to be a SG_TYPE.");
    for (Segment *s = (Segment *) (prog_base + elf->segments_offset); s->type != SG_NULL; s++) {
        if (s->type == type) return s;
    }
    print("get_segment failed to locate segment of type = ");
    print_hex(type);
    exit(1);
    return NULL;
}

void memcpy(void *dest, void *src, size_t n) {
    char *to = (char *) dest, *from = (char *) src;
    while (n--) *(to++) = *(from++);
}

#define ALIGN(value, alignment) (value & ~(alignment - 1))

typedef struct {
    void *plt_location;
    const char *symbol_name;
} _Relocation;

void link(char *prog_base, ELFHeader *elf) {
#define PATH_SIZE 1024
#define LIB_SIZE  256
#define REL_SIZE  1024
    uint64_t library_offsets[LIB_SIZE];  // TODO: dynamic array
    size_t lib_index = 0;
    void *got = NULL;
    char *string_table = NULL;
    uint64_t library_search_paths_offset = 0;
    Relocation *relocations = NULL;
    Symbol *symbol_table = NULL;

    Segment *dynamic_segment = get_segment(prog_base, elf, SG_DYNAMIC);
    for (Dynamic *d = (Dynamic *) (prog_base + dynamic_segment->offset); d->type != DN_NULL; d++) {
        // TODO: switch?
        if (d->type == DN_PLT_GOT) {
            got = (void *) d->value;
        } else if (d->type == DN_NEEDED) {
            assert(lib_index <= LIB_SIZE, "Too many shared libraries!");
            library_offsets[lib_index++] = d->value;
        } else if (d->type == DN_STRING_TABLE) {
            string_table = prog_base + d->value;
        } else if (d->type == DN_LIBRARY_SEARCH_PATHS) {
            library_search_paths_offset = d->value;
        } else if (d->type == DN_RELA || d->type == DN_REL || d->type == DN_RELR) {
            assert(0, "UNIMPLEMENTED: the only supported relocation type is REL_JUMP_SLOT.");
        } else if (d->type == DN_PLT_REL_TYPE) {
            assert(d->value == REL_JUMP_SLOT, "UNIMPLEMENTED: the only supported relocation type is REL_JUMP_SLOT.");
        } else if (d->type == DN_JUMP_RELOCATIONS) {
            relocations = (Relocation *) (prog_base + d->value);
        } else if (d->type == DN_SYMBOL_TABLE) {
            symbol_table = (Symbol *) (prog_base + d->value);
        }
    }
    assert(got != NULL, "Can't locate GOT.");
    assert(string_table != NULL, "Can't locate string table.");
    assert(symbol_table != NULL, "Can't locate symbol table.");
    assert(library_search_paths_offset != 0, "Can't locate library search paths.");
    assert(relocations != NULL, "Can't locate REL_JUMP_SLOT.");

    size_t ri = 0;
    _Relocation _relocations[REL_SIZE];  // TODO: dynamic array
    for (Relocation *r = relocations; r->offset; r++) {
        assert(r->addend == 0, "Error initializingi PLT: REL_JUMP_SLOT doesn't use addend.");
        assert(r->info.v.type == REL_JUMP_SLOT,
               "Error initializing PLT entries: relocation type must be REL_JUMP_SLOT.");

        Symbol s = symbol_table[r->info.v.symbol_index];
        assert(s.bind == SMB_GLOBAL || s.bind == SMB_WEAK,
               "Error initializing PLT: relocated symbol must have GLOBAL or WEAK binding.");
        assert(s.type == SMT_FUNC, "Error initializing PLT: relocated symbol must be of type FUNC.");
        assert(s.visibility == SMV_DEFAULT, "Error initializing PLT: relocated symbol must have DEFAULT visibility.");

        _relocations[ri].plt_location = prog_base + r->offset;
        _relocations[ri].symbol_name = string_table + s.name_offset;
        ri++;
    }

    char *library_search_path = string_table + library_search_paths_offset;
    char *p = library_search_path;
    while (*p) assert(*(p++) != ':', "UNIMPLEMENTED: multiple library search paths aren't implemented yet.");
    assert(library_search_path[0] == '/', "Library search paths must be absolute.");

    size_t library_search_path_length = strlen(library_search_path);
    char path_buffer[PATH_SIZE + 1];
    memcpy(path_buffer, library_search_path, library_search_path_length);
    path_buffer[library_search_path_length] = '/';
    library_search_path_length++;
    for (size_t i = 0; i < lib_index; i++) {
        char *library_name = string_table + library_offsets[i];
        size_t library_name_length = strlen(library_name);
        memcpy(path_buffer + library_search_path_length, library_name, library_name_length);
        path_buffer[library_search_path_length + library_name_length] = '\0';

        int fd = open(path_buffer, O_RDWR, NULL);
        if (fd == ENOENT) {
            print("Error loading shared library: unable to find library \"");
            print(library_name);
            print("\" at \"");
            print(library_search_path);
            print("\".\n");
        }

        ELFHeader lib_elf;
        read(fd, &lib_elf, sizeof(lib_elf));
        assert_supported_elf(&lib_elf);

        size_t lib_segments_size = 0;
        lseek(fd, lib_elf.segments_offset, SEEK_SET);
        for (size_t i = 0; i < lib_elf.segment_entry_count; i++) {
            Segment s;
            read(fd, &s, sizeof(s));

            if (s.type == SG_LOAD) {
                size_t new_size = s.address + s.memory_size;
                if (new_size > lib_segments_size) lib_segments_size = new_size;
            }
        }

        // memory of this mmap is not used, because the purpose of this call is to locate
        // contiguous chunk of address space which later gets overriden with library data
        char *lib_base = mmap(NULL, lib_segments_size, MAP_PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, NULL, NULL);
        assert(((int64_t) lib_base) > 0, "HANDLE SYS CALL ERROR");

        uint64_t previous_mapping_end = 0;
        lseek(fd, lib_elf.segments_offset, SEEK_SET);
        for (size_t i = 0; i < lib_elf.segment_entry_count; i++) {
            Segment s;
            read(fd, &s, sizeof(s));

            if (s.type == SG_LOAD) {
                assert(s.memory_size == s.file_size, "Segments with mem_size != file_size are unimplemented.");

                if (s.address % s.alignment != 0) {
                    assert(s.offset % s.alignment == s.address % s.alignment,
                           "Address and offset must be equally misaligned.");

                    uint64_t aligned_offset = ALIGN(s.offset, s.alignment);
                    uint64_t aligned_address = ALIGN(s.address, s.alignment);

                    s.file_size += s.offset - aligned_offset + s.file_size;
                    s.offset = aligned_offset;
                    s.address = aligned_address;
                }

                assert(s.address >= previous_mapping_end, "Mmaped segments overlap.");
                void *result = mmap(lib_base + s.address, s.file_size, s.flags, MAP_PRIVATE | MAP_FIXED, fd, s.offset);
                assert(((int64_t) result) > 0, "HANDLE SYS CALL ERROR");
                previous_mapping_end = s.address + s.file_size;
            }
        }
        close(fd);
    }
#undef REL_SIZE
#undef LIB_SIZE
#undef PATH_SIZE
}

void entry() {
    Args args = get_args();
    char *prog_base = get_prog_base(&args);
    ELFHeader *elf = (ELFHeader *) prog_base;
    assert_supported_elf(elf);

    main_t *main = (main_t *) (prog_base + elf->entry);
    int exit_code = main(args.argc, args.argv, args.envp);

    exit(exit_code);
}
