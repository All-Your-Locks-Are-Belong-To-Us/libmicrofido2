/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include "fido.h"

#include <stdint.h>

#if defined(NO_SOFTWARE_RNG)
fido_get_random_t fido_get_random = NULL;
#else
int get_random(const uint8_t *buf, size_t random_len) {
    // TODO: Implement randomness here according to the standard.
    return 0;
}
fido_get_random_t fido_get_random = get_random;
#endif
