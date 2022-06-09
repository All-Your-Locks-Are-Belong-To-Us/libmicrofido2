#########################################
# Config variables
#########################################

TOOLCHAIN_ROOT ?= /usr

CC := $(TOOLCHAIN_ROOT)/bin/avr-gcc
AR := $(TOOLCHAIN_ROOT)/bin/avr-ar

CPU := atmega1284p

EXTERNAL_LIBS :=

COMMONFLAGS := -Werror=shadow -mmcu=$(CPU)
LIBRARY_PREPROCESSOR_MACROS :=
EXAMPLES_PREPROCESSOR_MACROS :=
INCLUDE_DIRS := include
CFLAGS := -std=gnu99 -ffunction-sections -fdata-sections -fpack-struct -fshort-enums -Wall -Os
ARFLAGS :=

ifeq ($(DEBUG), 1)
	DEBUG_FLAGS := -ggdb
else
	DEBUG_FLAGS :=
endif

#########################################
# Directory settings
#########################################

BUILDDIR := build/
SOURCEDIR := src/
SOURCES := $(wildcard $(SOURCEDIR)/*.c)
OBJECTS := $(patsubst $(SOURCEDIR)/%.c,$(BUILDDIR)/%.o,$(SOURCES))
DEPS := $(OBJECTS:.o=.d)
EXAMPLEDIR := examples/
EXAMPLES := $(wildcard $(EXAMPLEDIR)/*.c)
EXAMPLES_BUILDDIR := $(BUILDDIR)/$(EXAMPLEDIR)
EXAMPLES_BINARIES := $(patsubst $(EXAMPLEDIR)/%.c,$(EXAMPLES_BUILDDIR)/%.elf,$(EXAMPLES))

LIBRARY_NAME := microfido2
TARGET := $(BUILDDIR)/lib$(LIBRARY_NAME).a

#########################################
# Flags
#########################################

LIBRARY_PREPROCESSOR_MACROS_EXPANDED := $(addprefix -D, $(LIBRARY_PREPROCESSOR_MACROS))
EXAMPLES_PREPROCESSOR_MACROS_EXPANDED := $(addprefix -D, $(EXAMPLES_PREPROCESSOR_MACROS))
CFLAGS += $(addprefix -I, $(INCLUDE_DIRS))

# Enable dependency rule generation
CFLAGS += -MMD
EXAMPLE_LDFLAGS := $(addprefix -l,$(LIBRARY_NAME)) -L$(BUILDDIR)

#########################################
# General targets
#########################################

.PHONY: all
all: $(TARGET)

.PHONY: clean
clean:
	$(RM) $(BUILDDIR)/**/*.o $(BUILDDIR)/**/*.d $(TARGET) $(EXAMPLES_BINARIES)

.PHONY: examples
examples: all $(EXAMPLES_BINARIES)

$(shell dirname $(BUILDDIR)):
	mkdir -p $(BUILDDIR)

$(shell dirname $(EXAMPLES_BUILDDIR)): $(BUILDDIR)
	mkdir $(EXAMPLES_BUILDDIR)

#########################################
# Compiling
#########################################

-include $(DEPS)

$(BUILDDIR)/%.o : $(SOURCEDIR)/%.c $(BUILDDIR)
	$(CC) $(COMMONFLAGS) $(CFLAGS) $(LIBRARY_PREPROCESSOR_MACROS_EXPANDED) $(DEBUG_FLAGS) -c $< -o $@

$(EXAMPLES_BUILDDIR)/%.elf : $(EXAMPLEDIR)/%.c $(EXAMPLES_BUILDDIR)
	$(CC) $(COMMONFLAGS) $(CFLAGS) $(EXAMPLES_PREPROCESSOR_MACROS_EXPANDED) $(DEBUG_FLAGS) $< $(EXAMPLE_LDFLAGS) -o $@

$(TARGET) : $(OBJECTS)
	$(AR) rcs $(ARFLAGS) $@ $?
