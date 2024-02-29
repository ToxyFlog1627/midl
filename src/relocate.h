#ifndef RELOCATE_H
#define RELOCATE_H

#include "elf.h"

void relocate_rela(char *rela_base, const ELFRela *rela, char *symbol_base, const ELFSymbol *symbol);

#endif  // RELOCATE_H