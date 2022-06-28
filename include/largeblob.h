/*
 * Copyright (c) 2020-2022 Yubico AB. All rights reserved.
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#pragma once

#include "dev.h"
#include <stdint.h>
#include <stddef.h>

#define LARGEBLOB_KEY_SIZE             (32)
#define LARGEBLOB_NONCE_SIZE           (12)
#define LARGEBLOB_ASSOCIATED_DATA_SIZE (12) // "blob" + 8 byte origSize

typedef struct fido_blob {
    uint8_t *buffer;
    size_t max_length;
    size_t length;
} fido_blob_t;

/**
 * @brief Reset a blob.
 *
 * @param blob Blob to reset.
 * @param buffer The new buffer.
 * @param buffer_len The length of the new buffer.
 */
void fido_blob_reset(fido_blob_t *blob, uint8_t *buffer, size_t buffer_len);

/**
 * @brief Read the serialized large-blob array.
 *
 * @param dev The device to read from.
 * @param largeblob_array The blob to load the data into.
 * @return success or failure
 */
int fido_dev_largeblob_get_array(fido_dev_t *dev, fido_blob_t *largeblob_array);

/**
 * @brief Get the blob that was encrypted with key.
 *
 * @param dev The device to read from.
 * @param key The AES key to use for decryption.
 * @param key_len The length of the AES key. Must be 32 byte.
 * @param blob The blob to load the data into.
 * @return success or failure
 */
int fido_dev_largeblob_get(fido_dev_t *dev, uint8_t *key, size_t key_len, fido_blob_t *blob);
