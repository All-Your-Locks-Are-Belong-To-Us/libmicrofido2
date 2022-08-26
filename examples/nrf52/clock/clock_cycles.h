/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#pragma once

#include <stdint.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/arch_interface.h>


extern volatile timing_t clock_cycle_start;

inline void clock_init() {
    arch_timing_init();
}

/**
 * @brief Starts counting clock cycles.
 * 
 */
static inline void clock_start_counting() {
    arch_timing_start();
    clock_cycle_start = arch_timing_counter_get();
}

/**
 * @brief Stops counting clock cycles and returns the number of elapsed cycles.
 * 
 */
static inline uint64_t clock_stop_counting() {
    timing_t end = arch_timing_counter_get();
    uint64_t val = arch_timing_cycles_get(&clock_cycle_start, &end);
    arch_timing_stop();
    return val;
}

/**
 * @brief Converts clock cycles to nanoseconds.
 * 
 * @param cycles The number of cycles.
 * @return uint64_t The number of nanoseconds.
 */
static inline uint64_t clock_cyles_to_ns(uint64_t cycles) {
    return arch_timing_cycles_to_ns(cycles);
}
