/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sdkconfig.h>

#include <fido.h>

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

#include <fido.h>
#include "stateless_rp/stateless_rp.h"
#include "stateless_rp/stateless_rp_nfc_simulator.h"

int app_main(void) {
    #ifdef CONFIG_USE_HW_CRYPTO
    init_crypto();
    #endif

    fido_dev_t dev;

    if (prepare_stateless_rp_nfc_simulator_device(&dev) != 0) {
        return 1;
    }

    const uint8_t updater_public_key[] = {0xA8, 0xEE, 0x4D, 0x2B, 0xD5, 0xAE, 0x09, 0x0A, 0xBC, 0xA9, 0x8A, 0x06, 0x6C, 0xA5, 0xB3, 0xA6, 0x22, 0x84, 0x89, 0xF5, 0x9E, 0x30, 0x90, 0x87, 0x65, 0x62, 0xB9, 0x79, 0x8A, 0xE7, 0x05, 0x15};
    return stateless_assert(&dev, "example.com", updater_public_key);
}
