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
EXTERNALS := cb0r

COMMONFLAGS := -Werror=shadow -mmcu=$(CPU)
LIBRARY_PREPROCESSOR_MACROS :=
EXAMPLES_PREPROCESSOR_MACROS :=
INCLUDE_DIRS := include
CFLAGS := -std=gnu99 -fstack-usage -ffunction-sections -fdata-sections -fpack-struct -fshort-enums -Wall
ARFLAGS :=
PREPROCESSOR_MACROS := _FIDO_INTERNAL

ifeq ($(DEBUG), 1)
	DEBUG_FLAGS := -ggdb -O0
else
	DEBUG_FLAGS := -Os
endif

#########################################
# Directory settings
#########################################

BUILDDIR := build
SOURCEDIR := src
EXTERNALDIR := external
SOURCES := $(wildcard $(SOURCEDIR)/*.c)
OBJECTS := $(patsubst $(SOURCEDIR)/%.c,$(BUILDDIR)/%.o,$(SOURCES))
EXAMPLEDIR := examples/
EXAMPLES := $(wildcard $(EXAMPLEDIR)/*.c)
EXAMPLES_BUILDDIR := $(BUILDDIR)/$(EXAMPLEDIR)
EXAMPLES_BINARIES := $(patsubst $(EXAMPLEDIR)/%.c,$(EXAMPLES_BUILDDIR)/%.elf,$(EXAMPLES))

LIBRARY_NAME := microfido2
TARGET := $(BUILDDIR)/lib$(LIBRARY_NAME).a

EXTERNAL_DIRS = $(addprefix $(EXTERNALDIR)/, $(EXTERNALS))
EXTERNAL_BUILDDIRS = $(addprefix $(BUILDDIR)/, $(EXTERNAL_DIRS))
EXTERNAL_INCLUDEDIRS = $(addsuffix /include, $(EXTERNAL_DIRS))
EXTERNAL_SOURCEDIRS = $(addsuffix /src, $(EXTERNAL_DIRS))
EXTERNAL_SOURCES := $(foreach srcdir, $(EXTERNAL_SOURCEDIRS), $(wildcard $(srcdir)/*.c))
EXTERNAL_OBJECTS := $(BUILDDIR)/$(subst src/,,$(EXTERNAL_SOURCES:.c=.o))

DEPS := $(OBJECTS:.o=.d) $(EXTERNAL_OBJECTS:.o=.d)

#########################################
# Flags
#########################################

LIBRARY_PREPROCESSOR_MACROS_EXPANDED := $(addprefix -D, $(LIBRARY_PREPROCESSOR_MACROS))
EXAMPLES_PREPROCESSOR_MACROS_EXPANDED := $(addprefix -D, $(EXAMPLES_PREPROCESSOR_MACROS))
CFLAGS += $(addprefix -I, $(INCLUDE_DIRS)) $(addprefix -I, $(EXTERNAL_INCLUDEDIRS))
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
	$(RM) $(shell find $(BUILDDIR) -name "*.o")\
		$(shell find $(BUILDDIR) -name "*.d")\
		$(shell find $(BUILDDIR) -name "*.su")\
		$(TARGET)\
		$(EXAMPLES_BINARIES)

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

$(TARGET) : $(EXTERNAL_OBJECTS) $(OBJECTS)
	$(AR) rcs $(ARFLAGS) $@ $?

define generateExternalRule
$(1):
	mkdir -p $(1)

$(1)/%.o: $(subst $(BUILDDIR)/,,$(1))/src/%.c $(1)
	$(CC) $$(COMMONFLAGS) $$(CFLAGS) $$(LIBRARY_PREPROCESSOR_MACROS_EXPANDED) $$(DEBUG_FLAGS) -c -o $$@ $$<
endef

$(foreach externalbuilddir, $(EXTERNAL_BUILDDIRS), $(eval $(call generateExternalRule, $(externalbuilddir))))
