/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#pragma once

#include <stdint.h>

/**
 * @brief Random number generation
 *
 * @param buf Pointer to the buffer to write the random bytes to.
 * @param random_len Amount of random bytes to generate.
 * @return int FIDO_OK when the random data was written successfully
 */
typedef int (*fido_get_random_t)(
    const uint8_t *buf,
    size_t random_len
);

/**
 * This is a pointer to a function for random number generation.
 * It can be set to other functions, for example when the platform provides
 * hardware support for RNGs.
 *
 * fido_get_random = &my_hardware_rng;
 *
 * You can define the macro NO_SOFTWARE_RNG to prevent the software implementation
 * of this algorithm to be included in the library.
 */
extern fido_get_random_t fido_get_random;
