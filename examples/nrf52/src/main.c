/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <zephyr/zephyr.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <fido.h>

#include "clock/clock_cycles.h"
#include "hw_crypto/hw_crypto.h"
#include "stateless_rp/stateless_rp_nfc_simulator.h"
#include "stateless_rp/stateless_rp.h"


int main(void) {
    clock_init();
    if (init_hw_crypto() != 0) {
        return -1;
    } else {
        printk("Initialized cryptography.\n");
    }

    fido_dev_t dev;
    if (prepare_stateless_rp_nfc_simulator_device(&dev) != 0) {
        printk("Could not setup simulator device.\n");
        return -1;
    }
    const uint8_t updater_public_key[] = {0xA8, 0xEE, 0x4D, 0x2B, 0xD5, 0xAE, 0x09, 0x0A, 0xBC, 0xA9, 0x8A, 0x06, 0x6C, 0xA5, 0xB3, 0xA6, 0x22, 0x84, 0x89, 0xF5, 0x9E, 0x30, 0x90, 0x87, 0x65, 0x62, 0xB9, 0x79, 0x8A, 0xE7, 0x05, 0x15};
    clock_start_counting();
    const int ret = stateless_assert(&dev, "example.com", updater_public_key);
    uint64_t elapsed_cycles = clock_stop_counting();
    printk("Elapsed cycles for stateless assertion: %zu\n", elapsed_cycles);
    return ret;
}
