#include "elf.h"
#include "ulibc.h"

void check_elf_header(ELFHeader *header) {
    assert(header->identifier.v.magic == ELF_MAGIC, "Error parsing ELF header: invalid magic.");
    assert(header->identifier.v.class == ELF_64, "Error parsing ELF header: ELF is not 64-bit.");
    assert(header->identifier.v.encoding == ELF_LSB, "Error parsing ELF header: ELF is not LSB.");
    assert(header->identifier.v.version == ELF_VERSION, "Error parsing ELF header: ELF version mismatch.");
    assert(header->identifier.v.abi == ELF_SYSV_ABI, "Error parsing ELF header: ABI type mismatch.");
    assert(header->identifier.v.abi_version == ELF_ABI_VERSION, "Error parsing ELF header: ABI version mismatch.");
    assert(header->type == ELF_EXEC_DYNAMIC, "Error parsing ELF header: ELF is not of type DYN.");
    assert(header->arch == ELF_AMD64, "Error parsing ELF header: CPU must be AMD64(x86_64).");
    assert(header->version == ELF_VERSION, "Error parsing ELF header: ELF version mismatch.");
}