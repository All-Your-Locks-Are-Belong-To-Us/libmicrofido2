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

// Endianess conversion tooling.
#if defined(__AVR__)
    // AVR is little endian.
    #define htole64(x) x
    #define be32toh(x) __builtin_bswap32(x)
#elif defined(__ZEPHYR__)
    #include <zephyr/sys/byteorder.h>
    #define htole64(x) sys_cpu_to_le64(x)
    #define be32toh(x) sys_be32_to_cpu(x)
#elif defined(__APPLE__)
    #include <libkern/OSByteOrder.h>
    #define htole64(x) OSSwapHostToLittleInt64(x)
    #define be32toh(x) OSSwapBigToHostInt32(x)
#elif defined(__has_include) && __has_include(<endian.h>) // Linux
    #include <endian.h>
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
