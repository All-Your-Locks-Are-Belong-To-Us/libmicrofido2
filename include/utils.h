/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#pragma once

#ifndef NULL
#define NULL ((void*)0)
#endif

#ifndef BITFIELD
    #define BITFIELD(x) (((uint64_t)1 << x))
#endif

#if defined(__AVR__)
    #define htole64(x) x
#else
    #error Unsupported architecture
#endif

#ifdef __AVR__
#include <avr/pgmspace.h>
#define PROGMEM_MARKER PROGMEM
#define memcmp_progmem memcmp_P
#else
#define PROGMEM_MARKER
#define memcmp_progmem memcmp
#define memcpy_progmem memcpy
#endif
