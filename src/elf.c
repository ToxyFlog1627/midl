#include "elf.h"
#include "ulibc.h"

void check_elf_header(const ELFHeader *header) {
    assert(header->identifier.v.magic == ELF_MAGIC, "Unable to parse ELF: invalid magic.");
    assert(header->identifier.v.class == ELF_64, "Unable to parse ELF: it is not 64-bit.");
    assert(header->identifier.v.encoding == ELF_LSB, "Unable to parse ELF: it is not LSB.");
    assert(header->identifier.v.version == ELF_VERSION, "Unable to parse ELF: version mismatch.");
    assert(header->identifier.v.abi == ELF_SYSV_ABI || header->identifier.v.abi == ELF_GNU_ABI,
           "Unable to parse ELF: ABI type mismatch.");
    assert(header->identifier.v.abi_version == ELF_ABI_VERSION, "Unable to parse ELF: ABI version mismatch.");
    assert(header->type == ELF_EXEC_DYNAMIC, "Unable to parse ELF: it is not of type DYN.");
    assert(header->arch == ELF_AMD64, "Unable to parse ELF: it is not built for x86_64.");
    assert(header->version == ELF_VERSION, "Unable to parse ELF: ELF version mismatch.");
}