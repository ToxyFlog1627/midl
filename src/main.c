#define NULL           0

#define SYS_READ       0x00
#define SYS_WRITE      0x01
#define SYS_OPEN       0x02
#define SYS_CLOSE      0x03
#define SYS_LSEEK      0x08
#define SYS_EXIT       0x3c
#define SYS_GETDENTS64 0xd9

#define STDIN          0
#define STDOUT         1
#define STDERR         2

#define O_RDONLY       0
#define O_WRONLY       1
#define O_RDWR         2

#define SEEK_SET       0
#define SEEK_CUR       1
#define SEEK_END       2

typedef long word;
typedef unsigned long size_t;
typedef unsigned long off_t;
typedef char bool;
typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int int16_t;
typedef short unsigned int uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long int int64_t;
typedef long unsigned int uint64_t;

#define PRINT_NUM_BUF_SIZE 32

#define ELF_MAGIC          0x464C457F
#define ELF_64             2
#define ELF_LSB            1
#define ELF_VERSION        1
#define ELF_SYSV_ABI       0
#define ELF_ABI_VERSION    0
#define ELF_EXEC_DYNAMIC   3
#define ELF_AMD64          62

typedef struct {
    union {
#pragma pack(push, 1)
        struct {
            uint32_t magic;
            uint8_t class;
            uint8_t encoding;
            uint8_t version;
            uint8_t abi;
            uint8_t abi_version;
        } v;
#pragma pack(pop)
        uint8_t raw[16];
    } identifier;
    uint16_t type;
    uint16_t arch;
    uint32_t version;
    uint64_t entry;  // TODO: void* or main*
    uint64_t segments_offset;
    uint64_t sections_offset;
    uint32_t flags;
    uint16_t size;
    uint16_t segment_entry_size;
    uint16_t segment_entry_count;
    uint16_t section_entry_size;
    uint16_t section_entry_count;
    uint16_t string_table_section_index;
} ELFHeader;

enum SG_TYPES {
    SG_NULL,
    SG_LOAD,
    SG_DYNAMIC,
    SG_INTERPRETER,
    SG_NOTE,
    __SG_SHLIB,  // unused
    SG_SEGMENT_TABLE,
    SG_THREAD_LOCAL_STORAGE,
    _SG_SIZE
};

#define SG_EXEC  0x1
#define SG_WRITE 0x2
#define SG_READ  0x4

typedef struct {
    uint32_t type;
    uint32_t flags;
    // TODO: what is the diff between adr and off
    uint64_t offset;
    uint64_t address;
    uint64_t __physical_address;  // unused
    uint64_t file_size;
    uint64_t memory_size;
    uint64_t alignment;
} Segment;

#define SC_WRITE 0x1
#define SC_ALLOC 0x2
#define SC_EXEC  0x4

#define SC_UNDEF 0

enum SC_TYPES {
    SC_NULL,
    SC_PROGRAM_INFO,
    SC_SYMBOL_TABLE,
    SC_STRING_TABLE,
    SC_RELOCATIONS,
    SC_HASH,
    SC_DYNAMIC,
    SC_NOTE,
    SC_UNINIT_SPACE,
    SC_REL,
    __SC_SHLIB,  // unused
    SC_DYNSYM,
    _SC_SIZE
};

typedef struct {
    uint32_t name_offset;
    uint32_t type;
    uint64_t flags;
    // TODO: what is the diff between adr and off
    uint64_t address;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
    uint32_t info;
    uint64_t alignment;
    uint64_t entry_size;
} Section;

typedef struct {
    uint64_t offset;
    union {
#pragma pack(push, 1)
        struct {
            int32_t symbol_index;
            int32_t type;
        } v;
#pragma pack(pop)
        uint64_t raw;
    } info;
    int64_t addend;
} Relocation;

typedef struct {
    int32_t name_offset;
    uint8_t type;
    uint8_t __unused;
    uint16_t section_index;
    uint64_t value;
    uint64_t size;
} Symbol;

enum DYNAMIC_TYPES {
    DN_NULL,
    DN_NEEDED,
    DN_PLT_SIZE,
    DN_PLT_GOT,
    DN_HASH,
    DN_STRING_TABLE,
    DN_SYMBOL_TABLE,
    DN_RELA,
    DN_RELA_SIZE,
    DN_RELA_ENTRY_SIZE,
    DN_STRING_TABLE_SIZE,
    DN_SYMBOL_ENTRY_SIZE,
    DN_INIT,
    DN_FINI,
    DN_SONAME,
    DN_RPATH,
    DN_SYMBOLIC,
    DN_REL,
    DN_RELSZ,
    DN_RELENT,
    DN_PLT_REL_TYPE,
    DN_DEBUG,
    DN_TEXTREL,
    DN_JMPREL,
    DN_BIND_NOW,
    DN_INIT_ARRAY,
    DN_FINI_ARRAY,
    DN_INIT_ARRAYSZ,
    DN_FINI_ARRAYSZ,
    DN_LIBRARY_SEARCH_PATHS,
    DN_FLAGS,
    DN_ENCODING,
    DN_PREINIT_ARRAY,
    DN_PREINIT_ARRAYSZ,
    DN_SYMTAB_SHNDX,
    DN_RELRSZ,
    DN_RELR,
    DN_RELRENT,
    _DN_SIZE
};

typedef struct {
    int64_t type;
    uint64_t value;
} Dynamic;

enum DE_TYPES {
    DE_UNKNOWN = 0,
    DE_FIFO = 1,
    DE_CHAR_DEV = 2,
    DE_DIR = 4,
    DE_BLOCK_DEV = 6,
    DE_FILE = 8,
    DE_LINK = 10,
    DE_SOCKET = 12
};

typedef struct {
    uint64_t inode;
    uint64_t offset;
    uint16_t size;
    uint8_t type;
    char *filename;
} dirent64;

word syscall(word call_num, word a1, word a2, word a3) {
    word retval;
    __asm__ volatile("syscall\n\t" : "=a"(retval) : "a"(call_num), "D"(a1), "S"(a2), "d"(a3));
    return retval;
}

#define read(fd, buf, len)          syscall(SYS_READ, fd, buf, len)
#define write(fd, buf, len)         syscall(SYS_WRITE, fd, ((word) (buf)), len)
#define open(path, flags, mode)     syscall(SYS_OPEN, path, flags, mode)
#define close(fd)                   syscall(SYS_CLOSE, fd, NULL, NULL)
#define lseek(fd, offset, whence)   syscall(SYS_LSEEK, fd, offset, whence)
#define exit(exit_code)             syscall(SYS_EXIT, exit_code, NULL, NULL)
#define getdents(fd, dirent, count) syscall(SYS_GETDENTS64, fd, direct, count)

// auxillary variable types
#define AT_NULL 0
#define AT_PHDR 3
#define AT_BASE 7

#define ENOENT  -0x02

typedef struct {
    int argc;
    char **argv;
    char **envp;
    word *auxv;
} Args;

typedef int main_t(int argc, char **argv, char **envp);

size_t strlen(const char *msg) {
    size_t len = 0;
    while (msg[len] != '\0') len++;
    return len;
}

int print(const char *msg) { return write(STDOUT, msg, strlen(msg)); }

int print_num(int64_t num) {
    char buffer[PRINT_NUM_BUF_SIZE];
    size_t i = 0, mask = 1;

    if (num < 0) {
        buffer[i++] = '-';
        num *= -1;
    }

    int64_t num_copy = num;
    do {
        mask *= 10;
        num_copy /= 10;
    } while (num_copy > 0);
    mask /= 10;

    do {
        buffer[i++] = '0' + (num / mask) % 10;
        mask /= 10;
    } while (mask > 0 && i < PRINT_NUM_BUF_SIZE);
    if (i + 1 >= PRINT_NUM_BUF_SIZE) return 1;

    buffer[i] = '\n';
    buffer[i + 1] = '\0';

    print(buffer);
    return 0;
}

int print_hex(uint64_t num) {
    char buffer[PRINT_NUM_BUF_SIZE];
    size_t i = 17;
    for (size_t j = 0; j <= i; j++) buffer[j] = '0';
    buffer[1] = 'x';
    buffer[i + 1] = '\n';
    buffer[i + 2] = '\0';

    while (num > 0) {
        uint8_t digit = num % 0x10;
        buffer[i--] = digit > 9 ? ('A' + digit - 10) : ('0' + digit);

        num >>= 4;
        if (i == 0) return 1;
    }

    print(buffer);
    return 0;
}

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

Segment *get_segment(char *prog_base, ELFHeader *elf, int type) {
    assert(type < _SG_SIZE, "Error in get_segment: expected type to be a SG_TYPE.");
    for (Segment *s = prog_base + elf->segments_offset; s->type != SG_NULL; s++) {
        if (s->type == type) return s;
    }
    print("get_segment failed to locate segment of type = ");
    print_hex(type);
    exit(1);
}

void memcpy(void *dest, void *src, size_t n) {
    char *to = (char *) dest, *from = (char *) src;
    while (n--) *(to++) = *(from++);
}

void link(char *prog_base, ELFHeader *elf) {
#define PATH_SIZE 1024
#define LIB_SIZE  256
    uint64_t library_offsets[LIB_SIZE] = {0};  // TODO: dynamic array
    size_t lib_index = 0;
    void *got = NULL;
    char *string_table = NULL;
    uint64_t library_search_paths_offset = NULL;

    Segment *dynamic_segment = get_segment(prog_base, elf, SG_DYNAMIC);
    for (Dynamic *d = prog_base + dynamic_segment->offset; d->type != DN_NULL; d++) {
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
        }
    }
    assert(got != NULL, "Can't locate GOT.");
    assert(string_table != NULL, "Can't locate string table.");
    assert(library_search_paths_offset != NULL, "Can't locate library search paths.");
    // TODO: use default paths (in /etc/ld.config or something)

    char *library_search_path = string_table + library_search_paths_offset;
    char *p = library_search_path;
    while (*p) assert(*(p++) != ':', "UNIMPLEMENTED: multiple library search paths aren't implemented yet.");  // TODO:
    assert(library_search_path[0] == '/', "Library search paths must be absolute.");

    // TODO: support proper library naming
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

        int fd = open(path_buffer, O_RDONLY, NULL);
        if (fd == ENOENT) {
            print("Error loading shared library: unable to find library \"");
            print(library_name);
            print("\" at \"");
            print(library_search_path);
            print("\".\n");
        }

        // TODO: load
        // TODO: should we open? I guess memmap'ping would be better
        // TODO: what does mmap do on non-existent file?
        close(fd);
    }
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
