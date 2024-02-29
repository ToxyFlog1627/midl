#ifndef SYM_H
#define SYM_H

#include "dyn.h"
#include "elf.h"

Symbol *find_symbol(const DynamicInfo *info, const char *symbol_name);

#endif  // SYM_H