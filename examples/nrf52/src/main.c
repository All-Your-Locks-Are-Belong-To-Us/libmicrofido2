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

#ifdef USE_HW_CRYPTO
#include <psa/crypto.h>
#endif

#include <fido.h>
#include "stateless_rp/stateless_rp.h"
#include "stateless_rp/stateless_rp_nfc_simulator.h"

#ifdef USE_HW_CRYPTO

void sha256(const uint8_t *data, size_t data_len, uint8_t *hash) {
    size_t olen; // We actually do not do anything with this parameter, but the API requires it.
    psa_status_t status = psa_hash_compute(
        PSA_ALG_SHA_256,
        data,
        data_len,
        hash,
        PSA_HASH_LENGTH(PSA_ALG_SHA_256),
        &olen
    );
    assert(status == PSA_SUCCESS);
}

void sha512(const uint8_t *data, size_t data_len, uint8_t *hash) {
    size_t olen; // We actually do not do anything with this parameter, but the API requires it.
    psa_status_t status = psa_hash_compute(
        PSA_ALG_SHA_512,
        data,
        data_len,
        hash,
        PSA_HASH_LENGTH(PSA_ALG_SHA_512),
        &olen
    );
    assert(status == PSA_SUCCESS);
}

int aes_gcm_encrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext, uint8_t *tag
) {
    psa_status_t status;
    int ret;
    const size_t tag_len = PSA_AEAD_TAG_LENGTH(PSA_KEY_TYPE_AES, key_len * 8, PSA_ALG_GCM);
    uint8_t cipher_buf[plaintext_len + tag_len];
    size_t cipher_size;


    // Import the key.
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&key_attributes, PSA_ALG_GCM);
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attributes, key_len * 8);

    psa_key_handle_t key_handle;
    
    status = psa_import_key(&key_attributes, key, key_len, &key_handle);
    if (status != PSA_SUCCESS) {
        printk("psa_import_key failed! (Error: %d)\n", status);
        ret = -1;
        goto out;
    }

    status = psa_aead_encrypt(
        key_handle,
        PSA_ALG_GCM,
        iv,
        iv_len,
        aad,
        aad_len,
        plaintext,
        plaintext_len,
        cipher_buf,
        sizeof(cipher_buf),
        &cipher_size
    );
    if (status != PSA_SUCCESS) {
        printk("psa_aead_encrypt failed! (Error: %d)\n", status);
        ret = -1;
        goto out;
    }
    assert(cipher_size == plaintext_len + tag_len);

    memcpy(ciphertext, cipher_buf, plaintext_len);
    memcpy(tag, cipher_buf + plaintext_len, tag_len);
    ret = 0;
out:
    memset(cipher_buf, 0, sizeof(cipher_buf));
    psa_reset_key_attributes(&key_attributes);
    status = psa_destroy_key(key_handle);
    if (status != PSA_SUCCESS) {
        printk("psa_destroy_key failed! (Error: %d)\n", status);
        ret = -1;
    }
    return ret;
}

int aes_gcm_decrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *tag,
    uint8_t *plaintext
) {
    psa_status_t status;
    int ret;
    const size_t tag_len = PSA_AEAD_TAG_LENGTH(PSA_KEY_TYPE_AES, key_len * 8, PSA_ALG_GCM);
    const size_t ciphertext_buf_len = ciphertext_len + tag_len;
    uint8_t ciphertext_buf[ciphertext_buf_len];
    uint8_t plaintext_buf[ciphertext_len];
    size_t decrypted_plaintext_size;

    // Import the key.
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&key_attributes, PSA_ALG_GCM);
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attributes, key_len * 8);

    psa_key_handle_t key_handle;
    
    status = psa_import_key(&key_attributes, key, key_len, &key_handle);
    if (status != PSA_SUCCESS) {
        printk("psa_import_key failed! (Error: %d)\n", status);
        ret = -1;
        goto out;
    }

    memcpy(ciphertext_buf, ciphertext, ciphertext_len);
    memcpy(ciphertext_buf + ciphertext_len, tag, tag_len);

    status = psa_aead_decrypt(
        key_handle,
        PSA_ALG_GCM,
        iv,
        iv_len,
        aad,
        aad_len,
        ciphertext_buf,
        ciphertext_buf_len,
        plaintext_buf,
        sizeof(plaintext_buf),
        &decrypted_plaintext_size
    );
    if (status != PSA_SUCCESS) {
        printk("psa_aead_encrypt failed! (Error: %d)\n", status);
        ret = -1;
        goto out;
    }

    if (decrypted_plaintext_size != ciphertext_len) {
        printk("Invalid plaintext length detected.\n");
        ret = -1;
        goto out;
    }

    memcpy(plaintext, plaintext_buf, decrypted_plaintext_size);
    ret = 0;
out:
    memset(plaintext_buf, 0, decrypted_plaintext_size);
    memset(ciphertext_buf, 0, ciphertext_buf_len);
    psa_reset_key_attributes(&key_attributes);
    status = psa_destroy_key(key_handle);
    if (status != PSA_SUCCESS) {
        printk("psa_destroy_key failed! (Error: %d)\n", status);
        ret = -1;
    }
    return ret;
}

int ed25519_sign(
    uint8_t *signature,
    const uint8_t *secret_key,
    const uint8_t *message,
    size_t message_len
) {
    psa_status_t status;
    int ret;

    // Import the key.
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&key_attributes, PSA_ALG_PURE_EDDSA);
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&key_attributes, 255); // Ed25519, see https://armmbed.github.io/mbed-crypto/html/api/keys/types.html#c.PSA_ECC_FAMILY_TWISTED_EDWARDS

    psa_key_handle_t key_handle;

    // Even though we set the key_type to a KEY_PAIR, we only need to import the secret key, as the library will derive the public key itself.
    status = psa_import_key(&key_attributes, secret_key, 32, &key_handle);
    if (status != PSA_SUCCESS) {
        printk("psa_import_key failed! (Error: %d)\n", status);
        ret = -1;
        goto out;
    }

    size_t signature_length;
    status = psa_sign_message(
        key_handle,
        PSA_ALG_PURE_EDDSA,
        message,
        message_len,
        signature,
        64,
        &signature_length
    );

    if (status != PSA_SUCCESS) {
        printk("psa_sign_message failed! (Error: %d)\n", status);
        ret = -1;
        goto out;
    }

    ret = 0;
out:
    psa_reset_key_attributes(&key_attributes);
    status = psa_destroy_key(key_handle);
    if (status != PSA_SUCCESS) {
        printk("psa_destroy_key failed! (Error: %d)\n", status);
        ret = -1;
    }
    return ret;
}

int ed25519_verify(
    const uint8_t *signature,
    const uint8_t *public_key,
    const uint8_t *message,
    size_t message_len
) {
    psa_status_t status;
    int ret;

    // Import the key.
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&key_attributes, PSA_ALG_PURE_EDDSA);
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&key_attributes, 255); // Ed25519, see https://armmbed.github.io/mbed-crypto/html/api/keys/types.html#c.PSA_ECC_FAMILY_TWISTED_EDWARDS

    psa_key_handle_t key_handle;

    status = psa_import_key(&key_attributes, public_key, 32, &key_handle);
    if (status != PSA_SUCCESS) {
        printk("psa_import_key failed! (Error: %d)\n", status);
        ret = -1;
        goto out;
    }

    status = psa_verify_message(
        key_handle,
        PSA_ALG_PURE_EDDSA,
        message,
        message_len,
        signature,
        64
    );

    if (status != PSA_SUCCESS) {
        printk("psa_verify_message failed! (Error: %d)\n", status);
        ret = -1;
        goto out;

    }
    ret = 0;
out:
    psa_reset_key_attributes(&key_attributes);
    status = psa_destroy_key(key_handle);
    if (status != PSA_SUCCESS) {
        printk("psa_destroy_key failed! (Error: %d)\n", status);
        ret = -1;
    }
    return ret;
}

int init_crypto() {
    if (psa_crypto_init() != PSA_SUCCESS) {
        return -1;
    }
    fido_sha256 = &sha256;
    fido_sha512 = &sha512;
    fido_aes_gcm_encrypt = &aes_gcm_encrypt;
    fido_aes_gcm_decrypt = &aes_gcm_decrypt;
    fido_ed25519_sign = &ed25519_sign;
    fido_ed25519_verify = &ed25519_verify;
    return 0;
}
#endif

int main(void) {
    #ifdef USE_HW_CRYPTO
    if (init_crypto() != 0) {
        printk("Failed to initialize hardware cryptography. Aborting.\n");
        return -1;
    } else {
        printk("Initialized hardware cryptography.\n");
    }

    const uint8_t key[32] = "YellowSubmarineYellowSubmarine";
    const uint8_t iv[12] = "123456789012";
    const uint8_t ad[6] = "kitten";
    const uint8_t plaintext[17] = "YellowSubmarineY";
    uint8_t decrypted_plaintext[sizeof(plaintext)] = {0};
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t tag[16];
    int e = aes_gcm_encrypt(key, sizeof(key), iv, sizeof(iv), plaintext, sizeof(plaintext), ad, sizeof(ad), ciphertext, tag);
    int f = aes_gcm_decrypt(key, sizeof(key), iv, sizeof(iv), ciphertext, sizeof(ciphertext), ad, sizeof(ad), tag, decrypted_plaintext);
    printk("AES encryption: %d %d\n", e, f);

    const uint8_t ed25519_private_key[] = {
        0x7D, 0x7C, 0x0A, 0x59, 0xA2, 0xAE, 0x18, 0x17, 0xCA, 0x23, 0x4D, 0x97, 0x77, 0x3D, 0xD6, 0xEE, 0x71, 0xFD, 0x81, 0x8A, 0xDB, 0xC9, 0x1F, 0x65, 0x3B, 0x43, 0x02, 0xC7, 0x2D, 0x4A, 0x4C, 0x22,
    };
    const uint8_t ed25519_public_key[] = {
        0xe8, 0x08, 0x65, 0x0a, 0x77, 0x1e, 0xbd, 0xb2, 0x4c, 0xe6, 0xd6, 0x1c, 0x0c, 0xf1, 0x85, 0x9c, 0x0e, 0xc1, 0xf5, 0x10, 0xec, 0x84, 0x6e, 0x10, 0xe6, 0x25, 0x77, 0xaa, 0x15, 0x82, 0x15, 0xa1,
    };
    uint8_t signature[64];
    const uint8_t sigmessage[6] = "kitten"; 
    int g = ed25519_sign(
        signature,
        ed25519_private_key,
        sigmessage,
        sizeof(sigmessage)
    );
    int h = ed25519_verify(
        signature,
        ed25519_public_key,
        sigmessage,
        sizeof(sigmessage)
    );
    printk("signature check: %d %d\n", g, h);
    #endif

    fido_dev_t dev;
    if (prepare_stateless_rp_nfc_simulator_device(&dev) != 0) {
        printk("Could not setup simulator device.\n");
        return -1;
    }
    const uint8_t updater_public_key[] = {0xA8, 0xEE, 0x4D, 0x2B, 0xD5, 0xAE, 0x09, 0x0A, 0xBC, 0xA9, 0x8A, 0x06, 0x6C, 0xA5, 0xB3, 0xA6, 0x22, 0x84, 0x89, 0xF5, 0x9E, 0x30, 0x90, 0x87, 0x65, 0x62, 0xB9, 0x79, 0x8A, 0xE7, 0x05, 0x15};
    return stateless_assert(&dev, "example.com", updater_public_key);
}
