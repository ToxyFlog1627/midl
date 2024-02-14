#define NULL 0

#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_OPEN 2
#define SYS_CLOSE 3
#define SYS_LSEEK 8
#define SYS_EXIT 60

#define STDIN 0
#define STDOUT 1
#define STDERR 2

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

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

#define BUF_SIZE 32

#define ELF_MAGIC 0x464C457F
#define ELF_64 2
#define ELF_LSB 1
#define ELF_VERSION 1
#define ELF_SYSV_ABI 0
#define ELF_ABI_VERSION 0
#define ELF_EXEC_DYNAMIC 3
#define ELF_AMD64 62

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
    SG_THREAD_LOCAL_STORAGE
};

#define SG_EXEC 0x1
#define SG_WRITE 0x2
#define SG_READ 0x4

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
#define SC_EXEC 0x4

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
    SC_DYNSYM
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
    DT_NULL,
    DT_NEEDED,
    DT_PLT_SIZE,
    DT_PLT_GOT,
    DT_HASH,
    DT_STRING_TABLE,
    DT_SYMBOL_TABLE,
    DT_RELOCATION,
    DT_RELOCATION_SIZE,
    DT_RELOCATION_ENTRY_SIZE,
    DT_STRING_SIZE,
    DT_SYMBOL_ENTRY,
    DT_INIT,
    DT_FINI,
    DT_SONAME,
    DT_RPATH,
    DT_SYMBOLIC,
    DT_REL,
    DT_RELSZ,
    DT_RELENT,
    DT_PLTREL,
    DT_DEBUG,
    DT_TEXTREL,
    DT_JMPREL,
    DT_BIND_NOW,
    DT_INIT_ARRAY,
    DT_FINI_ARRAY,
    DT_INIT_ARRAYSZ,
    DT_FINI_ARRAYSZ,
    DT_RUNPATH,
    DT_FLAGS,
    DT_ENCODING,
    DT_PREINIT_ARRAY,
    DT_PREINIT_ARRAYSZ,
    DT_SYMTAB_SHNDX,
    DT_RELRSZ,
    DT_RELR,
    DT_RELRENT
};

typedef struct {
    int64_t type;
    uint64_t value;
} Dynamic;

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

word syscall(word call_num, word a1, word a2, word a3) {
    word retval;
    __asm__ volatile("syscall\n\t" : "=a"(retval) : "a"(call_num), "D"(a1), "S"(a2), "d"(a3));
    return retval;
}

#define read(fd, buf, len) syscall(SYS_READ, fd, buf, len)
#define write(fd, buf, len) syscall(SYS_WRITE, fd, ((word) (buf)), len)
#define open(path, flags, mode) syscall(SYS_OPEN, path, flags, mode)
#define close(fd) syscall(SYS_CLOSE, fd, NULL, NULL)
#define lseek(fd, offset, whence) syscall(SYS_LSEEK, fd, offset, whence)
#define exit(exit_code) syscall(SYS_EXIT, exit_code, NULL, NULL)

size_t strlen(const char *msg) {
    size_t len = 0;
    while (msg[len] != '\0') len++;
    return len;
}

int print(const char *msg) { return write(STDOUT, msg, strlen(msg)); }

int print_num(int64_t num) {
    char buffer[BUF_SIZE];
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
    } while (mask > 0 && i < BUF_SIZE);
    if (i + 1 >= BUF_SIZE) return 1;

    buffer[i] = '\n';
    buffer[i + 1] = '\0';

    print(buffer);
    return 0;
}

int print_hex(uint64_t num) {
    char buffer[BUF_SIZE];
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

char *get_program_base(Args *args) {
    word *var = args->auxv;
    while (*var != AT_PHDR) {
        var += 2;
        assert(var != NULL, "Error parsing auxillary variables: expected AT_PHDR.");
    }

    Segment *phdr = (Segment *) (*(var + 1));
    return (char *) (((word) phdr) - phdr->offset);
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
