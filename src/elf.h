#ifndef ELF_H
#define ELF_H

#include "types.h"

// Header

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
    uint64_t entry;
    uint64_t segments_offset;
    uint64_t sections_offset;
    uint32_t flags;
    uint16_t size;
    uint16_t segment_entry_size;
    uint16_t segment_entry_num;
    uint16_t section_entry_size;
    uint16_t section_entry_num;
    uint16_t string_table_section_index;
} ELFHeader;

// Segment (Program Header)

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
    uint64_t file_offset;
    uint64_t memory_offset;
    uint64_t __physical_address;  // unused
    uint64_t file_size;
    uint64_t memory_size;
    uint64_t alignment;
} ELFSegment;

// Rela

enum RELA_TYPES { RL_NONE, RL_64, RL_PC32, RL_GOT32, RL_PLT32, RL_COPY, RL_GLOB_DAT, RL_JUMP_SLOT, RL_RELATIVE };

enum RELA_SYMBOL_TYPE { RST_NOTYPE, RST_OBJECT, RST_FUNC, RST_SECTION, RST_FILE, RST_COMMON, RST_TLS };

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
} ELFRela;

// Symbol

enum SYMBOL_BINDING_TYPES { SMB_LOCAL, SMB_GLOBAL, SMB_WEAK };

enum SYMBOL_TYPES { SMT_NOTYPE, SMT_OBJECT, SMT_FUNC, SMT_SECTION, SMT_FILE, SMT_COMMON, SMT_TLS };

enum SYMBOL_VISIBILITY_TYPES { SMV_DEFAULT, SMV_INTERNAL, SMV_HIDDEN, SMV_PROTECTED };

typedef struct {
    uint32_t name_offset;
    uint8_t type : 4, binding : 4;
    uint8_t visibility : 3, __unused : 5;
    uint16_t section_index;
    uint64_t value;
    uint64_t size;
} ELFSymbol;

// Dynamic

enum DYNAMIC_TYPES {
    DN_NULL,
    DN_NEEDED,
    DN_PLT_REL_SIZE,
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
    DN_SO_NAME,
    DN_RUNTIME_PATH,
    DN_SYMBOLIC,
    DN_REL,
    DN_REL_SIZE,
    DN_REL_ENTRY_SIZE,
    DN_PLT_REL_TYPE,
    DN_DEBUG,
    DN_TEXT_REL,
    DN_JUMP_RELOCS,
    DN_BIND_NOW,
    DN_INIT_ARRAY,
    DN_FINI_ARRAY,
    DN_INIT_ARRAY_SIZE,
    DN_FINI_ARRAY_SIZE,
    DN_LIBRARY_SEARCH_PATHS,
    DN_FLAGS,
    DN_ENCODING,
    DN_PREINIT_ARRAY,
    DN_PREINIT_ARRAY_SIZE,
    DN_SYMTAB_SHARED_IDX,
    DN_RELR_SIZE,
    DN_RELR,
    DN_RELR_ENTRY_SIZE,
    _DN_SIZE,
    DN_GNU_HASH = 0x6FFFFEF5,
    DN_FLAGS_1 = 0x6FFFFFFB
};

typedef struct {
    int64_t type;
    uint64_t value;
} ELFDynamic;

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
} GNUHashTable;

// Helpers

void check_elf_header(const ELFHeader *header);

#endif  // ELF_H