/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include "fido.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void *example_open() {
    return (void*)1; // Just return a fake handle for this device.
};

static void example_close(void *handle) {
}

static int example_read(void *handle, unsigned char *buf, const size_t len) {
    return 0;
}

static int example_write(void *handle, const unsigned char *buf, const size_t len) {
    return 0;
}

static const fido_dev_io_t nfc_io = {
    .open = example_open,
    .close = example_close,
    .read = example_read,
    .write = example_write
};

int main(void) {
    fido_dev_t dev;
    if (fido_init_nfc_device(&dev, &nfc_io) != FIDO_OK) {
        return 1;
    }

    if (fido_dev_open(&dev) != FIDO_OK) {
        return 2;
    }

    fido_assert_t assert;
    fido_assert_reset(&assert);
    const char *rpid = "wau.felixgohla.de";
    fido_assert_set_rp(&assert, rpid);
    fido_assert_set_extensions(&assert, FIDO_ASSERT_EXTENSION_LARGE_BLOB_KEY);
    int r = fido_dev_get_assert(&dev, &assert);
    if (r != FIDO_OK) {
        return 3;
    }

    // Retrieve large blob.
    uint8_t key[] = {
        0xCA, 0x97, 0x81, 0x12, 0xCA, 0x1B, 0xBD, 0xCA, 0xFA, 0xC2, 0x31, 0xB3, 0x9A, 0x23, 0xDC, 0x4D, 0xA7, 0x86, 0xEF, 0xF8, 0x14, 0x7C, 0x4E, 0x72, 0xB9, 0x80, 0x77, 0x85, 0xAF, 0xEE, 0x48, 0xBB,
        // from Chromium
        // 0xF7, 0x8E, 0x65, 0x59, 0xF4, 0xE8, 0x70, 0xF2, 0xF0, 0x37, 0x41, 0x63, 0x85, 0x31, 0xEF, 0x31, 0x50, 0x8F, 0x76, 0x18, 0x73, 0x4B, 0x68, 0x7A, 0x4A, 0x42, 0x16, 0x65, 0xEA, 0x6A, 0x7F, 0xA2,
    };
    fido_blob_t blob;
    uint8_t outbuf[1024] = {0};
    fido_blob_reset(&blob, outbuf, sizeof(outbuf));
    if (fido_dev_largeblob_get(&dev, key, sizeof(key), &blob) != FIDO_OK) {
        return 4;
    }

    fido_assert_verify(&assert, -8, NULL);

    if (fido_dev_close(&dev) != FIDO_OK) {
        return 5;
    }

    return 0;
}
