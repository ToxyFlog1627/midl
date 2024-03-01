#include "relocate.h"
#include "elf.h"
#include "library.h"
#include "ulibc.h"
#include "vector.h"

typedef struct {
    char *loc;
    const char *symbol_name
} GOTSymbol;

DEF_VECTOR_T(GOTSymbol, vec_got_symbols);

static vec_got_symbols gots;

void relocate_rela(char *rela_base, const ELFRela *rela, char *symbol_base, const ELFSymbol *symbol,
                   const char *symbol_name) {
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
            for (size_t i = 0; i < gots.length; i++) {
                if (strcmp(gots.data[i].symbol_name, symbol_name) == 0) {
                    memcpy(rela_base + rela->offset, gots.data[i].loc, symbol->size);
                    break;
                }
            }
            break;
        case RL_GLOB_DAT:
            GOTSymbol got = {symbol_base + symbol->value, strdup(symbol_name)};
            VECTOR_PUSH(gots, got);
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