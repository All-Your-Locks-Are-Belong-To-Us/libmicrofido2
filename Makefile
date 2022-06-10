#
# Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
#                    Quentin Kuth, Felix Roth. All rights reserved.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
#

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
CFLAGS := -std=gnu99 -fstack-usage -ffunction-sections -fdata-sections -fpack-struct -fshort-enums -Wall -Os
ARFLAGS :=
PREPROCESSOR_MACROS := _FIDO_INTERNAL

ifeq ($(DEBUG), 1)
	DEBUG_FLAGS := -ggdb
else
	DEBUG_FLAGS :=
endif

#########################################
# Directory settings
#########################################

BUILDDIR := build
SOURCEDIR := src
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
CFLAGS += $(addprefix -D, $(PREPROCESSOR_MACROS))

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

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(EXAMPLES_BUILDDIR): $(BUILDDIR)
	mkdir -p $(EXAMPLES_BUILDDIR)

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
