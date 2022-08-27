/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#pragma once

#include <stdint.h>
#include <esp_cpu.h>
#include <esp_rom_sys.h>

extern volatile esp_cpu_cycle_count_t clock_cycle_start;

inline void clock_init() {}

/**
 * @brief Starts counting clock cycles.
 * 
 */
static inline void clock_start_counting() {
    clock_cycle_start = esp_cpu_get_cycle_count();
}

/**
 * @brief Stops counting clock cycles and returns the number of elapsed cycles.
 * 
 */
static inline uint64_t clock_stop_counting() {
    esp_cpu_cycle_count_t end = esp_cpu_get_cycle_count();
    uint64_t val = end - clock_cycle_start;
    return val;
}

/**
 * @brief Converts clock cycles to nanoseconds.
 *
 * @param cycles The number of cycles.
 * @return uint64_t The number of nanoseconds.
 */
static inline uint32_t clock_cyles_to_ns(uint64_t cycles) {
    return cycles * 1000 / esp_rom_get_cpu_ticks_per_us();
}
