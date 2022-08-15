/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <sdkconfig.h>

#ifdef CONFIG_USE_HW_CRYPTO
#include "fido.h"

#include <stdio.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

void sha256(const uint8_t *data, size_t data_len, uint8_t *hash) {
    int r = mbedtls_sha256(data, data_len, hash, 0);
    if (r != 0) {
        printf("sha256 failed with %d\n", r);
    }
}

void sha512(const uint8_t *data, size_t data_len, uint8_t *hash) {
    int r = mbedtls_sha512(data, data_len, hash, 0);
    if (r != 0) {
        printf("sha512 failed with %d\n", r);
    }
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
        plaintext, ciphertext,
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

    r = mbedtls_gcm_auth_decrypt(
        &ctx,
        ciphertext_len,
        iv, iv_len,
        aad, aad_len,
        tag, 16,
        ciphertext, plaintext
    );
    if (r != 0) {
        printf("[%s] mbedtls_gcm_auth_decrypt failed with %d\n", __func__, r);
        return r;
    }

    mbedtls_gcm_free(&ctx);

    return 0;
}

int init_hw_crypto() {
    fido_sha256 = &sha256;
    fido_sha512 = &sha512;
    fido_aes_gcm_encrypt = &aes_gcm_encrypt;
    fido_aes_gcm_decrypt = &aes_gcm_decrypt;

    return 0;
}
#else
int init_hw_crypto() {
    return 0;
}
#endif
