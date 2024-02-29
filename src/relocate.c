#include "relocate.h"
#include "elf.h"
#include "library.h"
#include "ulibc.h"

void relocate_rela(char *rela_base, const ELFRela *rela, char *symbol_base, const ELFSymbol *symbol) {
    switch (rela->info.v.type) {
        case RL_64:
            UNIMPLEMENTED("RL_64");
            break;
        case RL_PC32:
            UNIMPLEMENTED("RL_PC32");
            break;
        case RL_GOT32:
            UNIMPLEMENTED("RL_GOT32");
            break;
        case RL_PLT32:
            UNIMPLEMENTED("RL_PLT32");
            break;
        case RL_COPY:
            UNIMPLEMENTED("RL_COPY");
            break;
        case RL_GLOB_DAT:
        case RL_JUMP_SLOT:
            *((uint64_t *) (rela_base + rela->offset)) = (uint64_t) (symbol_base + symbol->value);
            break;
        case RL_RELATIVE:
            UNIMPLEMENTED("RL_RELATIVE");
            break;
        default:
            print("ERROR: Unkown relocation type.");
            exit(1);
    }
}