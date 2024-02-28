#include "ulibc.h"
#include "print.h"
#include "syscalls.h"
#include "types.h"

typedef struct _MemoryChunk {
    size_t size;
    struct _MemoryChunk *next;
} MemoryChunk;

static MemoryChunk *free_list = NULL, *used_list = NULL;
static char *heap_end = NULL;

#define PTR_TO_MEM_CHUNK(ptr)       ((MemoryChunk *) (((char *) ptr) - sizeof(MemoryChunk)));
#define MEM_CHUNK_TO_PTR(mem_chunk) (((char *) mem_chunk) + sizeof(MemoryChunk))

__attribute__((noreturn)) void exit(int exit_code) {
    _exit(exit_code);
    __builtin_unreachable();
}

void assert(bool condition, const char *error_msg) {
    if (!condition) {
        print(error_msg);
        if (error_msg[strlen(error_msg) - 1] != '\n') print("\n");
        exit(1);
    }
}

void memcpy(void *dest, const void *src, size_t n) {
    char *to = (char *) dest, *from = (char *) src;
    while (n--) *(to++) = *(from++);
}

// NOTE: this partial implementation always returns 1 if strings are different
int memcmp(const void *s1, const void *s2, size_t n) {
    if (n == 0) return 0;

    char *p1 = (char *) s1, *p2 = (char *) s2;
    while (*(p1++) == *(p2++) && --n > 0) continue;
    return n;
}

void memset(void *s, char c, size_t n) {
    char *p = s;
    while (n--) *(p++) = c;
}

void *malloc(size_t n) {
    // TODO: align
    assert(n != 0, "UNIMPLEMENTED");
    if (heap_end == NULL) heap_end = brk(0);

    for (MemoryChunk *prev = NULL, *cur = free_list; cur != NULL; prev = cur, cur = cur->next) {
        // TODO: don't use whole chunk
        if (cur->size >= n) {
            if (prev) prev->next = cur->next;
            else free_list = cur->next;

            cur->next = used_list;
            used_list = cur;

            return MEM_CHUNK_TO_PTR(cur);
        }
    }

    MemoryChunk *new_chunk = (MemoryChunk *) heap_end;
    heap_end = brk(heap_end + n + sizeof(MemoryChunk));
    new_chunk->size = n;
    new_chunk->next = used_list;
    used_list = new_chunk;
    return MEM_CHUNK_TO_PTR(new_chunk);
}

void free(void *ptr) {
    assert(ptr != NULL, "UNIMPLEMENTED");
    MemoryChunk *chunk = PTR_TO_MEM_CHUNK(ptr);
    for (MemoryChunk *prev = NULL, *cur = used_list; cur != NULL; prev = cur, cur = cur->next) {
        if (cur == chunk) {
            if (prev) prev->next = cur->next;
            else used_list = cur->next;

            chunk->next = free_list;
            free_list = chunk;

            // TODO: merge free chunks of memory

            return;
        }
    }
    assert(false, "Freeing memory without mallocing it.");
}

void *realloc(void *ptr, size_t n) {
    assert(n != 0, "UNIMPLEMENTED");
    assert(ptr != NULL, "UNIMPLEMENTED");
    void *new_ptr = malloc(n);
    MemoryChunk *chunk = PTR_TO_MEM_CHUNK(ptr);
    assert(n > chunk->size, "UNIMPLEMENTED");
    memcpy(new_ptr, ptr, chunk->size);
    free(ptr);
    return new_ptr;
}