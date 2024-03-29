CC      := gcc
CFLAGS  := -std=c17 -Wall -Wextra -pedantic -O0

ifeq ($(DEBUG),1)
	CFLAGS += -ggdb -g3 -DDEBUG
else
	CFLAGS += -s
endif

BUILD_DIR  := build
OBJECT_DIR := objs

LD_SRC_DIR   := src
LD_BUILD_DIR := $(BUILD_DIR)/loader
LD_OBJ_DIR   := $(LD_BUILD_DIR)/$(OBJECT_DIR)

SOURCES := $(shell find $(LD_SRC_DIR) -type f -name '*.c')
LOADER  := $(LD_BUILD_DIR)/loader.so
OBJECTS := $(patsubst $(LD_SRC_DIR)/%.c, $(LD_OBJ_DIR)/%.o, $(SOURCES))

EXAMPLES := libless single_lib chained_libs multiple_libs reused_lib got_init

EX_BIN_CFLAGS := $(CFLAGS) -e main -Wl,--dynamic-linker,$(PWD)/$(LOADER) -nostdlib
EX_LIB_CFLAGS := $(CFLAGS) -shared -nostdlib

EX_BIN_SRC_DIR   := examples
EX_LIB_SRC_DIR   := examples/libs

EX_BIN_BUILD_DIR := $(BUILD_DIR)/$(EX_BIN_SRC_DIR)
EX_BIN_OBJ_DIR   := $(EX_BIN_BUILD_DIR)/$(OBJECT_DIR)
EX_LIB_BUILD_DIR := $(BUILD_DIR)/$(EX_LIB_SRC_DIR)
EX_LIB_OBJ_DIR   := $(EX_LIB_BUILD_DIR)/$(OBJECT_DIR)


.PHONY: all
all: build examples

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

.PHONY: build
build: $(LOADER)

.PHONY: examples
examples: $(patsubst %, $(EX_BIN_BUILD_DIR)/%, $(EXAMPLES))

$(LOADER): $(OBJECTS)
	$(CC) $(CFLAGS) -e entry -nostdlib -o $@ $^ -shared -Wl,-z,now -Wl,-Bstatic -Wl,-no-dynamic-linker -Wl,--dynamic-list=$(PWD)/export.txt

$(LD_OBJ_DIR)/%.o: $(LD_SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I src -o $@ -c $^ -fno-stack-protector -Wno-builtin-declaration-mismatch

$(EX_LIB_BUILD_DIR)/libmath.so: $(EX_LIB_OBJ_DIR)/math.o
	@mkdir -p $(@D)
	$(CC) $(EX_LIB_CFLAGS) $^ -o $@

$(EX_LIB_BUILD_DIR)/libsyscall.so: $(EX_LIB_OBJ_DIR)/syscall.o
	@mkdir -p $(@D)
	$(CC) $(EX_LIB_CFLAGS) $^ -o $@

$(EX_LIB_BUILD_DIR)/libprint.so: $(EX_LIB_OBJ_DIR)/print.o $(EX_LIB_BUILD_DIR)/libsyscall.so
	@mkdir -p $(@D)
	$(CC) $(EX_LIB_CFLAGS) -L $(EX_LIB_BUILD_DIR) -Wl,-rpath=$(PWD)/$(EX_LIB_BUILD_DIR) -o $@ $< -lsyscall

$(EX_LIB_BUILD_DIR)/libtime.so: $(EX_LIB_SRC_DIR)/time.c $(EX_LIB_BUILD_DIR)/libsyscall.so
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -fPIC -o $(EX_LIB_OBJ_DIR)/time.o -c $(EX_LIB_SRC_DIR)/time.c -fno-stack-protector
	$(CC) $(EX_LIB_CFLAGS) -L $(EX_LIB_BUILD_DIR) -Wl,-rpath=$(PWD)/$(EX_LIB_BUILD_DIR) -Wl,-init=initialize_time -o $@ $(EX_LIB_OBJ_DIR)/time.o -lsyscall

$(EX_LIB_OBJ_DIR)/%.o: $(EX_LIB_SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $^ -fno-stack-protector

$(EX_BIN_BUILD_DIR)/libless: $(EX_BIN_OBJ_DIR)/libless.o
	@mkdir -p $(@D)
	$(CC) $(EX_BIN_CFLAGS) -o $@ $^

$(EX_BIN_BUILD_DIR)/single_lib: $(EX_BIN_OBJ_DIR)/single_lib.o $(EX_LIB_BUILD_DIR)/libmath.so
	@mkdir -p $(@D)
	$(CC) $(EX_BIN_CFLAGS) -o $@ $< -Wl,-rpath=$(PWD)/$(EX_LIB_BUILD_DIR) -L $(EX_LIB_BUILD_DIR) -lmath

$(EX_BIN_BUILD_DIR)/chained_libs: $(EX_BIN_OBJ_DIR)/chained_libs.o $(EX_LIB_BUILD_DIR)/libprint.so
	@mkdir -p $(@D)
	$(CC) $(EX_BIN_CFLAGS) -o $@ $< -Wl,-rpath=$(PWD)/$(EX_LIB_BUILD_DIR) -L $(EX_LIB_BUILD_DIR) -lprint -Wno-unused-parameter

$(EX_BIN_BUILD_DIR)/multiple_libs: $(EX_BIN_OBJ_DIR)/multiple_libs.o $(EX_LIB_BUILD_DIR)/libprint.so $(EX_LIB_BUILD_DIR)/libmath.so
	@mkdir -p $(@D)
	$(CC) $(EX_BIN_CFLAGS) -o $@ $< -Wl,-rpath=$(PWD)/$(EX_LIB_BUILD_DIR) -L $(EX_LIB_BUILD_DIR) -lprint -lmath -Wno-unused-parameter

$(EX_BIN_BUILD_DIR)/reused_lib: $(EX_BIN_OBJ_DIR)/reused_lib.o $(EX_LIB_BUILD_DIR)/libprint.so $(EX_LIB_BUILD_DIR)/libsyscall.so
	@mkdir -p $(@D)
	$(CC) $(EX_BIN_CFLAGS) -o $@ $< -Wl,-rpath=$(PWD)/$(EX_LIB_BUILD_DIR) -L $(EX_LIB_BUILD_DIR) -lprint -lsyscall -Wno-unused-parameter

$(EX_BIN_BUILD_DIR)/got_init: $(EX_BIN_OBJ_DIR)/got_init.o $(EX_LIB_BUILD_DIR)/libprint.so $(EX_LIB_BUILD_DIR)/libtime.so
	@mkdir -p $(@D)
	$(CC) $(EX_BIN_CFLAGS) -o $@ $< -Wl,-rpath=$(PWD)/$(EX_LIB_BUILD_DIR) -L $(EX_LIB_BUILD_DIR) -lprint -ltime -Wno-unused-parameter

$(EX_BIN_OBJ_DIR)/%.o: $(EX_BIN_SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $^ -fno-stack-protector
