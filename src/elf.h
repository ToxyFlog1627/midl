#ifndef ELF_H
#define ELF_H

#include "types.h"

#define ELF_MAGIC        0x464C457F
#define ELF_64           2
#define ELF_LSB          1
#define ELF_VERSION      1
#define ELF_SYSV_ABI     0
#define ELF_ABI_VERSION  0
#define ELF_EXEC_DYNAMIC 3
#define ELF_AMD64        62

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

enum SEGMENT_TYPES {
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

enum SECTION_TYPES {
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

#define REL_NONE      0
#define REL_64        1
#define REL_PC32      2
#define REL_GOT32     3
#define REL_PLT32     4
#define REL_COPY      5
#define REL_GLOB_DAT  6
#define REL_JUMP_SLOT 7
#define REL_RELATIVE  8

#define RELST_NOTYPE  0
#define RELST_OBJECT  1
#define RELST_FUNC    2
#define RELST_SECTION 3
#define RELST_FILE    4
#define RELST_COMMON  5
#define RELST_TLS     6

typedef struct {
    uint64_t offset;
    union {
#pragma pack(push, 1)
        struct {
            int32_t type;
            int32_t symbol_index;
        } v;
#pragma pack(pop)
        uint64_t raw;
    } info;
    int64_t addend;
} Relocation;

#define SMB_LOCAL     0
#define SMB_GLOBAL    1
#define SMB_WEAK      2

#define SMT_NOTYPE    0
#define SMT_OBJECT    1
#define SMT_FUNC      2
#define SMT_SECTION   3
#define SMT_FILE      4
#define SMT_COMMON    5
#define SMT_TLS       6

#define SMV_DEFAULT   0
#define SMV_INTERNAL  1
#define SMV_HIDDEN    2
#define SMV_PROTECTED 3

typedef struct {
    uint32_t name_offset;
    uint8_t type : 4, bind : 4;
    uint8_t visibility : 3, __unused : 5;
    uint16_t section_index;
    uint64_t value;
    uint64_t size;
} Symbol;

// TODO: rename types
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
    DN_JUMP_RELOCATIONS,
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
    _DN_SIZE,
    DN_GNU_HASH = 0x6FFFFEF5
};

typedef struct {
    int64_t type;
    uint64_t value;
} Dynamic;

// https://sourceware.org/legacy-ml/binutils/2006-10/msg00377.html
// GNU Hash Table:

// Dynamic symbols section is split into two parts:
// 1. one that can't be looked up using GNU hash table (up to first_symbol_index)
// 2. one that can and is sorted by their hash table index (to improve CPU caching and prefetching)
typedef struct {
    uint32_t buckets_num;
    uint32_t first_symbol_index;
    uint32_t bloom_size;
    uint32_t bloom_shift;
    uint64_t *bloom_filter;
    uint32_t *buckets;
    uint32_t *chains;
} HashTable;

uint32_t elf_gnu_hash(const char *s) {
    uint32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s) h = h * 33 + c;
    return h;
}

bool elf_gnu_bloom_test(const HashTable *h, uint32_t hash) {
    uint64_t word = h->bloom_filter[(hash / 64) % h->bloom_size];
    uint64_t mask = (((uint64_t) 1) << (hash % 64)) | (((uint64_t) 1) << ((hash >> h->bloom_shift) % 64));
    return (word & mask) == mask;
}

#endif  // ELF_H