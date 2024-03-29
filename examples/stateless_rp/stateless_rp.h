/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#pragma once

#include <fido.h>

/**
 * @brief Perform a stateless RP assertion (à la Baumann et al.).
 *
 * @param dev The (initialized) device to use.
 * @param rp_id The RP ID to use.
 * @param updater_public_key The public key of the updater that signed the content of the large blob.
 * @return 0 on success, an error code otherwise.
 */
int stateless_assert(fido_dev_t *dev_t, const char *rp_id, const uint8_t *updater_public_key);
