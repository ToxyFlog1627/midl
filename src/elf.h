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

#endif  // ELF_H