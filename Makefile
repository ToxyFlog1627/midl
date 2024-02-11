CC      := gcc
CFLAGS  := -std=c17 -Wall -Wextra -pedantic

ifeq ($(DEBUG),1)
	CFLAGS += -ggdb -g3 -DDEBUG -O0
else
	CFLAGS += -s -O2
endif

SOURCE_DIR  := src
BUILD_DIR   := build
OBJECTS_DIR := $(BUILD_DIR)/$(SOURCE_DIR)
EXAMPLE_DIR := example
LIB_SRC_DIR := example/lib

SOURCES := $(shell find $(SOURCE_DIR) -type f -name '*.c')
LOADER  := $(BUILD_DIR)/loader.so
LIBRARY := $(BUILD_DIR)/libprint.so
EXAMPLE := $(BUILD_DIR)/ex

OBJECTS := $(patsubst $(SOURCE_DIR)/%.c, $(OBJECTS_DIR)/%.o, $(SOURCES))

.PHONY: all
all: build

.PHONY: build
build: $(LOADER) $(LIBRARY) $(EXAMPLE)

.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)

.PHONY: $(LOADER)
$(LOADER): $(OBJECTS)
	$(CC) $(CFLAGS) -e entry -nostdlib $^ -o $@ -static-pie

$(OBJECTS_DIR)/%.o: $(SOURCE_DIR)/%.c
	@mkdir -p $(BUILD_DIR)/$(SOURCE_DIR)
	$(CC) $(CFLAGS) -I src -c $^ -o $@ -fno-stack-protector

.PHONY: $(EXAMPLE)
$(EXAMPLE): $(EXAMPLE_DIR)/example.c $(LOADER) $(LIBRARY)
	@mkdir -p $(BUILD_DIR)/$(EXAMPLE_DIR)
	$(CC) $(CFLAGS) -I $(LIB_SRC_DIR) -c $(EXAMPLE_DIR)/example.c -o $(BUILD_DIR)/$(EXAMPLE_DIR)/example.o
	$(CC) $(CFLAGS) -e main -Wl,--dynamic-linker,$(shell realpath $(LOADER)) -nostdlib $(BUILD_DIR)/$(EXAMPLE_DIR)/example.o -o $@

.PHONY: $(LIBRARY)
$(LIBRARY): $(LIB_SRC_DIR)/print.c
	@mkdir -p $(BUILD_DIR)/$(LIB_SRC_DIR)
	$(CC) $(CFLAGS) -c $^ -o $(BUILD_DIR)/$(LIB_SRC_DIR)/print.o
	$(CC) $(CFLAGS) -nodefaultlibs -shared $(BUILD_DIR)/$(LIB_SRC_DIR)/print.o -o $@
