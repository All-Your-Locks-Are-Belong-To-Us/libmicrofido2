/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <fido.h>

/**
 * @brief Prepares a device with simulated NFC output for testing the stateless Relying Party.
 *
 * It works by mocking the I/O functions with returning a synthetic NFC communication.
 * 
 * @param dev A pointer to the device to mock.
 * @return 0 on success.
 */
int prepare_stateless_rp_nfc_simulator_device(fido_dev_t *dev);
