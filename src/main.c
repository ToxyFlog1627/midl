#include "dyn.h"
#include "elf.h"
#include "lib.h"
#include "print.h"
#include "sym.h"
#include "syscalls.h"
#include "types.h"
#include "ulibc.h"
#include "vector.h"

#define AT_NULL 0
#define AT_PHDR 3

typedef struct {
    int argc;
    char **argv;
    char **envp;
    word *auxv;
} Args;

typedef int main_t(int argc, char **argv, char **envp);
typedef void void_fun_t(void);

static vec_lib_info loaded_libs;

#define FUN_PTR_CAST(fun_ptr) *((void **) &(fun_ptr))

static Args get_args() {
    word ptr;
    __asm__ volatile("mov (%%rbp), %[ret]\n\t" : [ret] "=r"(ptr));
    ptr += sizeof(word);  // skip old call frame

    Args args;

    args.argc = *((size_t *) ptr);
    args.argv = ((char **) (ptr)) + 1;
    args.envp = args.argv + args.argc + 1;
    args.auxv = (word *) args.envp;
    while (*(args.auxv++)) continue;

    return args;
}

static char *get_prog_base(Args *args) {
    word *var = args->auxv;
    while (*var != AT_PHDR) {
        var += 2;
        assert(var != AT_NULL, "Error in get_prog_base: couldn't find variable of type AT_PHDR.");
    }

    Segment *phdr = (Segment *) (*(var + 1));
    return (char *) (((word) phdr) - phdr->file_offset);
}

static bool is_library_loaded(const char *lib_name) {
    for (size_t j = 0; j < loaded_libs.length; j++) {
        if (strcmp(loaded_libs.elements[j].name, lib_name) == 0) return true;
    }
    return false;
}

static void relocate_rela(char *rel_base, const Rela *rela, char *sym_base, const Symbol *sym) {
    switch (rela->info.v.type) {
        case RL_64:
            assert(0, "RL_64 UNIMPLEMENTED");
            break;
        case RL_PC32:
            assert(0, "RL_PC32 UNIMPLEMENTED");
            break;
        case RL_GOT32:
            assert(0, "RL_GOT32 UNIMPLEMENTED");
            break;
        case RL_PLT32:
            assert(0, "RL_PLT32 UNIMPLEMENTED");
            break;
        case RL_COPY:
            assert(0, "RL_COPY UNIMPLEMENTED");
            break;
        case RL_GLOB_DAT:
        case RL_JUMP_SLOT:
            *((uint64_t *) (rel_base + rela->offset)) = (uint64_t) (sym_base + sym->value);
            break;
        case RL_RELATIVE:
            assert(0, "RL_RELATIVE UNIMPLEMENTED");
            break;
        default:
            print("Unkown relocation type.\n");
            exit(1);
            break;
    }
}

static void relocate_relas(char *base, const DynamicInfo *info, Rela *relas, size_t relas_count) {
    Rela *rela = relas;
    for (size_t i = 0; i < relas_count; i++, rela++) {
        Symbol *rel_sym = info->symbol_table + rela->info.v.symbol_index;
        const char *symbol_name = info->string_table + rel_sym->name_offset;

        Symbol *sym = find_symbol(info, symbol_name);
        if (sym) {
            relocate_rela(base, rela, base, sym);
            continue;
        }

        for (size_t j = 0; j < loaded_libs.length; j++) {
            LibInfo lib_info = loaded_libs.elements[j];
            sym = find_symbol(&lib_info.dyn_info, symbol_name);
            if (sym) {
                relocate_rela(base, rela, lib_info.base, sym);
                break;
            }
        }
        assert(sym != NULL, "UNIMPLEMENTED");
    }
}

static void resolve_symbols(char *base, const DynamicInfo *info) {
    for (size_t i = 0; i < info->needed_libs.length; i++) {
        const char *lib_name = info->needed_libs.elements[i];
        if (is_library_loaded(lib_name)) continue;

        LibInfo lib_info;
        load_library(&lib_info, &info->lib_search_paths, lib_name);
        VECTOR_PUSH(loaded_libs, lib_info);

        resolve_symbols(lib_info.base, &lib_info.dyn_info);

        if (lib_info.dyn_info.init) {
            void_fun_t *init;
            FUN_PTR_CAST(init) = lib_info.dyn_info.init;
            init();
        }
    }

    if (info->jump_relocs) relocate_relas(base, info, info->jump_relocs, info->jump_relocs_count);
    if (info->relas) relocate_relas(base, info, info->relas, info->rela_count);
}

void entry() {
    Args args = get_args();
    char *prog_base = get_prog_base(&args);
    ELFHeader *prog_elf = (ELFHeader *) prog_base;
    check_elf_header(prog_elf);

    DynamicInfo prog_info;
    get_dynamic_info(&prog_info, prog_base, prog_elf);

    resolve_symbols(prog_base, &prog_info);

    main_t *main;
    FUN_PTR_CAST(main) = prog_base + prog_elf->entry;
    int exit_code = main(args.argc, args.argv, args.envp);

    // TODO: fini

    exit(exit_code);
}

// TODO: for .so dynamic linker, change type, add README, etc.
// extern Elf32_Dyn _DYNAMIC[];
// extern Elf32_Addr _GLOBAL_OFFSET_TABLE_[];