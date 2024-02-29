#include "ulibc.h"
#include "syscalls.h"
#include "types.h"

typedef struct _MemoryChunk {
    size_t size;
    struct _MemoryChunk *next;
} MemoryChunk;

#define PRINT_NUM_BUF_SIZE 32

static MemoryChunk *free_list = NULL, *used_list = NULL;
static char *heap_end = NULL;

#define PTR_TO_MEM_CHUNK(ptr)       ((MemoryChunk *) (((char *) ptr) - sizeof(MemoryChunk)));
#define MEM_CHUNK_TO_PTR(mem_chunk) (((char *) mem_chunk) + sizeof(MemoryChunk))

__attribute__((noreturn)) void exit(int exit_code) {
    _exit(exit_code);
    __builtin_unreachable();
}

void assert(bool condition, const char *error_message) {
    if (condition) return;

    print(error_message);
    if (error_message[strlen(error_message) - 1] != '\n') print("\n");
    exit(1);
}

int print(const char *message) { return write(STDOUT, message, strlen(message)); }

int print_num(int64_t num) {
    char buffer[PRINT_NUM_BUF_SIZE];
    size_t i = 0, mask = 1;

    if (num < 0) {
        buffer[i++] = '-';
        num *= -1;
    }

    int64_t num_copy = num;
    do {
        mask *= 10;
        num_copy /= 10;
    } while (num_copy > 0);
    mask /= 10;

    do {
        buffer[i++] = '0' + (num / mask) % 10;
        mask /= 10;
    } while (mask > 0 && i < PRINT_NUM_BUF_SIZE);
    if (i + 1 >= PRINT_NUM_BUF_SIZE) return 1;

    buffer[i] = '\n';
    buffer[i + 1] = '\0';

    print(buffer);
    return 0;
}

int print_hex(uint64_t num) {
    char buffer[PRINT_NUM_BUF_SIZE];
    size_t i = 17;
    for (size_t j = 0; j <= i; j++) buffer[j] = '0';
    buffer[1] = 'x';
    buffer[i + 1] = '\n';
    buffer[i + 2] = '\0';

    while (num > 0) {
        uint8_t digit = num % 0x10;
        buffer[i--] = digit > 9 ? ('A' + digit - 10) : ('0' + digit);

        num >>= 4;
        if (i == 0) return 1;
    }

    print(buffer);
    return 0;
}

size_t strlen(const char *message) {
    size_t len = 0;
    while (message[len] != '\0') len++;
    return len;
}

// NOTE: this partial implementation always returns 1 if strings are different
int strcmp(const char *s1, const char *s2) {
    while (*s1 && *s2 && *s1 == *s2) {
        s1++;
        s2++;
    }

    if (*s1 == '\0' && *s2 == '\0') return 0;
    return 1;
}

char *strdup(const char *s) {
    size_t len = strlen(s);
    char *copy = (char *) malloc(len + 1);
    memcpy(copy, s, len);
    copy[len] = '\0';
    return copy;
}

void memcpy(void *dest, const void *src, size_t n) {
    char *to = (char *) dest, *from = (char *) src;
    while (n--) *(to++) = *(from++);
}

// NOTE: this partial implementation always returns 1 if data is different
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
    if (n == 0) return NULL;

    if (heap_end == NULL) heap_end = brk(0);

    for (MemoryChunk *prev = NULL, *cur = free_list; cur != NULL; prev = cur, cur = cur->next) {
        if (cur->size < n) continue;

        // TODO: don't use whole chunk
        if (prev) prev->next = cur->next;
        else free_list = cur->next;

        cur->next = used_list;
        used_list = cur;

        return MEM_CHUNK_TO_PTR(cur);
    }

    MemoryChunk *new_chunk = (MemoryChunk *) heap_end;
    heap_end = brk(heap_end + n + sizeof(MemoryChunk));
    new_chunk->size = n;
    new_chunk->next = used_list;
    used_list = new_chunk;
    return MEM_CHUNK_TO_PTR(new_chunk);
}

void free(void *ptr) {
    assert(ptr != NULL, "Unable to free NULL.");
    MemoryChunk *chunk = PTR_TO_MEM_CHUNK(ptr);
    for (MemoryChunk *prev = NULL, *cur = used_list; cur != NULL; prev = cur, cur = cur->next) {
        if (cur != chunk) continue;

        if (prev) prev->next = cur->next;
        else used_list = cur->next;

        chunk->next = free_list;
        free_list = chunk;

        // TODO: merge free chunks of memory

        return;
    }
    assert(false, "Trying to free pointer which wasn't malloced.");
}

void *realloc(void *ptr, size_t n) {
    assert(n != 0, "Trying to realloc with size 0.");
    assert(ptr != NULL, "Trying to realloc NULL pointer.");
    void *new_ptr = malloc(n);
    MemoryChunk *chunk = PTR_TO_MEM_CHUNK(ptr);
    assert(n > chunk->size, "Trying to shrink memory with realloc");
    memcpy(new_ptr, ptr, chunk->size);
    free(ptr);
    return new_ptr;
}