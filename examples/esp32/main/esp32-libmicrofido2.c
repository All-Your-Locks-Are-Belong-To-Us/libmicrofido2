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
#include <sdkconfig.h>

#ifdef CONFIG_USE_HW_CRYPTO
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#endif

#ifdef CONFIG_USE_HW_CRYPTO
int sha256(const uint8_t *data, size_t data_len, uint8_t *hash) {
    int r = mbedtls_sha256(data, data_len, hash, 0);
    if (r != 0) {
        printf("sha256 failed with %d\n", r);
    }
    return r;
}

int sha512(const uint8_t *data, size_t data_len, uint8_t *hash) {
    int r = mbedtls_sha512(data, data_len, hash, 0);
    if (r != 0) {
        printf("sha512 failed with %d\n", r);
    }
    return r;
}

int aes_gcm_encrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext, uint8_t *tag
) {
    mbedtls_gcm_context ctx;
    int r;

    mbedtls_gcm_init(&ctx);

    r = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);
    if (r != 0) {
        printf("[%s] mbedtls_gcm_setkey failed with %d\n", __func__, r);
        return r;
    }

    r = mbedtls_gcm_crypt_and_tag(
        &ctx,
        MBEDTLS_ENCRYPT,
        plaintext_len,
        iv, iv_len,
        aad, aad_len,
        ciphertext, plaintext,
        16, tag
    );
    if (r != 0) {
        printf("[%s] mbedtls_gcm_crypt_and_tag failed with %d\n", __func__, r);
        return r;
    }

    mbedtls_gcm_free(&ctx);

    return 0;
}

int aes_gcm_decrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *tag,
    uint8_t *plaintext
) {
    mbedtls_gcm_context ctx;
    int r;

    mbedtls_gcm_init(&ctx);

    r = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);
    if (r != 0) {
        printf("[%s] mbedtls_gcm_setkey failed with %d\n", __func__, r);
        return r;
    }

    r = mbedtls_gcm_crypt_and_tag(
        &ctx,
        MBEDTLS_DECRYPT,
        ciphertext_len,
        iv, iv_len,
        aad, aad_len,
        ciphertext, plaintext,
        16, tag
    );
    if (r != 0) {
        printf("[%s] mbedtls_gcm_crypt_and_tag failed with %d\n", __func__, r);
        return r;
    }

    mbedtls_gcm_free(&ctx);

    return 0;
}

void init_crypto() {
    fido_sha256 = &sha256;
    fido_sha512 = &sha512;
    fido_aes_gcm_encrypt = &aes_gcm_encrypt;
    fido_aes_gcm_decrypt = &aes_gcm_decrypt;
}
#endif

static void *example_open() {
    printf("open\n");
    return (void*)1; // Just return a fake handle for this device.
};

static void example_close(void *handle) {
    printf("close\n");
}

enum fido_state {
    FIDO_STATE_UNINIT = 0,
    FIDO_STATE_APPLET_SELECTION,
    FIDO_STATE_GET_INFO,
    FIDO_STATE_GET_LARGE_BLOB,
};

static enum fido_state sim_state = FIDO_STATE_UNINIT;

static int example_read(void *handle, unsigned char *buf, const size_t len) {
    printf("trying to read %zu bytes\n", len);
    switch (sim_state)
    {
        case FIDO_STATE_APPLET_SELECTION:
            {
                static const uint8_t app_select_response[] = "U2F_V2";
                static const size_t version_length = sizeof(app_select_response) - 1;
                assert(len >= version_length + 2);
                memcpy(buf, app_select_response, version_length);
                buf[version_length] = 0x90;
                buf[version_length + 1] = 0x00;
                return version_length + 2;
            }

        case FIDO_STATE_GET_INFO:
            {
                // Send get info response.
                // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo
                static const uint8_t get_info_response[] = {
                    FIDO_OK,
                    // {1: ["FIDO_2_1"], 2: ["largeBlobKey"], 3: h'30313233343536373839303132333435', 4: {"largeBlobs": true}, 5: 2048, 9: ["nfc"], 11: 1024}
                    0xA7, 0x01, 0x81, 0x68, 0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x31, 0x02, 0x81, 0x6C, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x42, 0x6C, 0x6F, 0x62, 0x4B, 0x65, 0x79, 0x03, 0x50, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x04, 0xA1, 0x6A, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x42, 0x6C, 0x6F, 0x62, 0x73, 0xF5, 0x05, 0x19, 0x08, 0x00, 0x09, 0x81, 0x63, 0x6E, 0x66, 0x63, 0x0B, 0x19, 0x04, 0x00,
                    0x90, 0x00,
                };
                assert(len >= sizeof(get_info_response));
                memcpy(buf, get_info_response, sizeof(get_info_response));
                return sizeof(get_info_response);
            }
        case FIDO_STATE_GET_LARGE_BLOB:
            {
                // plaintext: kitten
                // key: 0xCA, 0x97, 0x81, 0x12, 0xCA, 0x1B, 0xBD, 0xCA, 0xFA, 0xC2, 0x31, 0xB3, 0x9A, 0x23, 0xDC, 0x4D, 0xA7, 0x86, 0xEF, 0xF8, 0x14, 0x7C, 0x4E, 0x72, 0xB9, 0x80, 0x77, 0x85, 0xAF, 0xEE, 0x48, 0xBB
                // [{1: h'53cbebb35d0cf479372a10a94892d8bbfc47a67257cb22958ad655455efb98cd', 2: h'33582CB89E78D63967801A77', 3: 6}]
                static const uint8_t get_large_blob_response[] = {
                    FIDO_OK,
                    // {1: h'81A301582053CBEBB35D0CF479372A10A94892D8BBFC47A67257CB22958AD655455EFB98CD024C33582CB89E78D63967801A7703060b66d4ae669185b3f4722c5f576e172d'}
                    0xA1, 0x01, 0x58, 0x45, 0x81, 0xA3, 0x01, 0x58, 0x20, 0x53, 0xCB, 0xEB, 0xB3, 0x5D, 0x0C, 0xF4, 0x79, 0x37, 0x2A, 0x10, 0xA9, 0x48, 0x92, 0xD8, 0xBB, 0xFC, 0x47, 0xA6, 0x72, 0x57, 0xCB, 0x22, 0x95, 0x8A, 0xD6, 0x55, 0x45, 0x5E, 0xFB, 0x98, 0xCD, 0x02, 0x4C, 0x33, 0x58, 0x2C, 0xB8, 0x9E, 0x78, 0xD6, 0x39, 0x67, 0x80, 0x1A, 0x77, 0x03, 0x06, 0x0B, 0x66, 0xD4, 0xAE, 0x66, 0x91, 0x85, 0xB3, 0xF4, 0x72, 0x2C, 0x5F, 0x57, 0x6E, 0x17, 0x2D,
                    // from Chromium.
                    // 0xA1, 0x01, 0x58, 0xAC, 0x81, 0xA3, 0x01, 0x58, 0x86, 0x7D, 0xB9, 0x8C, 0x5B, 0x62, 0xC6, 0x84, 0x4A, 0x89, 0xAC, 0x92, 0x87, 0x25, 0x32, 0xE0, 0x09, 0xCF, 0xD6, 0xFB, 0x86, 0x5A, 0xB8, 0x36, 0xF3, 0xD2, 0x46, 0xC7, 0xBD, 0x98, 0x69, 0x9C, 0x9B, 0x6F, 0x42, 0x2F, 0x25, 0xB0, 0x29, 0xCC, 0x6B, 0xAF, 0xB0, 0xE8, 0x33, 0xB4, 0x5F, 0xF7, 0x96, 0x33, 0x3D, 0xED, 0x38, 0x59, 0x95, 0x2F, 0x8B, 0x02, 0x9C, 0x03, 0x09, 0xC9, 0xAE, 0x75, 0xAC, 0x37, 0xC8, 0xB4, 0x70, 0x5D, 0xBB, 0x9D, 0x7D, 0x75, 0xE4, 0x90, 0x50, 0x71, 0xF2, 0x43, 0x7E, 0x77, 0x4C, 0xD6, 0xE1, 0xC1, 0xBA, 0xE2, 0x69, 0x95, 0x23, 0x72, 0xC9, 0x8E, 0xEE, 0xB7, 0x51, 0xED, 0xB5, 0xB0, 0x25, 0x00, 0x81, 0x18, 0xAA, 0xD4, 0xAF, 0x59, 0xC6, 0xF4, 0x8E, 0x84, 0x63, 0x91, 0x97, 0x6F, 0x10, 0xF8, 0xF6, 0x92, 0x34, 0x15, 0x1E, 0x34, 0x52, 0xD4, 0x2A, 0x9E, 0xCA, 0x96, 0x9C, 0x34, 0x5F, 0x68, 0x95, 0x02, 0x4C, 0x6A, 0x26, 0x7B, 0x79, 0x97, 0xBE, 0x23, 0x44, 0x60, 0x33, 0x65, 0xA1, 0x03, 0x18, 0x71, 0x46, 0x86, 0x64, 0x52, 0x87, 0xB8, 0x0B, 0x74, 0x11, 0xEA, 0x56, 0x19, 0xB9, 0xD2, 0x96, 0xDD,
                    0x90, 0x00,
                };
                assert(len >= sizeof(get_large_blob_response));
                memcpy(buf, get_large_blob_response, sizeof(get_large_blob_response));
                return sizeof(get_large_blob_response);
            }
    case FIDO_STATE_UNINIT:
    default:
        return 0;
        break;
    }
}

static int example_write(void *handle, const unsigned char *buf, const size_t len) {
    // Output the buffer.
    printf("writing: ");
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", buf[i]);
    }
    putc('\n', stdout);

    // Stupid state machine, that does not know anything about parsing the message completely.
    switch (sim_state) {
        case FIDO_STATE_UNINIT:
            sim_state = FIDO_STATE_APPLET_SELECTION;
            break;
        case FIDO_STATE_APPLET_SELECTION:
            sim_state = FIDO_STATE_GET_INFO;
            break;
        case FIDO_STATE_GET_INFO:
            sim_state = FIDO_STATE_GET_LARGE_BLOB;
            break;
        default: break;
    }
    return (int)len;
}

static const fido_dev_io_t nfc_io = {
    .open = example_open,
    .close = example_close,
    .read = example_read,
    .write = example_write
};

int app_main(void) {
    #ifdef CONFIG_USE_HW_CRYPTO
    init_crypto();
    #endif

    fido_dev_t dev;
    if (fido_init_nfc_device(&dev, &nfc_io) != FIDO_OK) {
        return 1;
    }

    if (fido_dev_open(&dev) != FIDO_OK) {
        return 2;
    }

    // Retrieve large blob.
    uint8_t key[] = {
        0xCA, 0x97, 0x81, 0x12, 0xCA, 0x1B, 0xBD, 0xCA, 0xFA, 0xC2, 0x31, 0xB3, 0x9A, 0x23, 0xDC, 0x4D, 0xA7, 0x86, 0xEF, 0xF8, 0x14, 0x7C, 0x4E, 0x72, 0xB9, 0x80, 0x77, 0x85, 0xAF, 0xEE, 0x48, 0xBB,
        // from Chromium
        // 0xF7, 0x8E, 0x65, 0x59, 0xF4, 0xE8, 0x70, 0xF2, 0xF0, 0x37, 0x41, 0x63, 0x85, 0x31, 0xEF, 0x31, 0x50, 0x8F, 0x76, 0x18, 0x73, 0x4B, 0x68, 0x7A, 0x4A, 0x42, 0x16, 0x65, 0xEA, 0x6A, 0x7F, 0xA2,
    };
    fido_blob_t blob;
    uint8_t outbuf[2048] = {0};
    fido_blob_reset(&blob, outbuf, sizeof(outbuf));
    if (fido_dev_largeblob_get(&dev, key, sizeof(key), &blob) != FIDO_OK) {
        return 3;
    }

    if (fido_dev_close(&dev) != FIDO_OK) {
        return 4;
    }

    return 0;
}
