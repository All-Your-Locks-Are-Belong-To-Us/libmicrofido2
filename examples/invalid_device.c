/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include "fido.h"

int main(void) {
    fido_dev_t device;
    fido_dev_init(&device);
    
    // This should fail because the io and transport functions are not set for the device.
    fido_dev_open(&device);

    // Always close your devices.
    fido_dev_close(&device);
}
