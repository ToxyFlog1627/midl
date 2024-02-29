#ifndef SYMBOL_H
#define SYMBOL_H

#include "dynamic.h"
#include "elf.h"

ELFSymbol *find_symbol(const Dynamic *dynamic, const char *symbol_name);

#endif  // SYMBOL_H