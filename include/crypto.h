#pragma once

#include <stdint.h>
#include <stddef.h>

#ifndef AES_GCM_TAG_SIZE
#define AES_GCM_TAG_SIZE  16
#endif

#ifndef SHA256_BLOCK_SIZE
#define SHA256_BLOCK_SIZE 32
#endif

/**
 * @brief AES GCM encrypt
 *
 * @param key Pointer to the key.
 * @param key_len Length of the key in bytes (e.g. 32 for 256 bit AES).
 * @param iv Pointer to initialization vector (IV).
 * @param iv_len Length of the IV in bytes.
 * @param plaintext Pointer to the plaintext to encrypt.
 * @param plaintext_len Length of the plaintext in bytes.
 * @param aad Pointer to data to associate with the ciphertext.
 * @param aad_len Length of the associated data in bytes.
 * @param ciphertext Pointer to where to write the ciphertext to. May be the same as plaintext.
 * @param tag Pointer to where to write the 16 byte long authentication tag to.
 * @return 0 on success.
 */
typedef int (*fido_aes_gcm_encrypt_t)(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext, uint8_t *tag);

/**
 * @brief AES GCM decrypt
 *
 * @param key Pointer to the key.
 * @param key_len  Length of the key in bytes (e.g. 32 for 256 bit AES).
 * @param iv Pointer to the initialization vector (IV).
 * @param iv_len Length of the IV in bytes.
 * @param ciphertext Pointer to the ciphertext to decrypt.
 * @param ciphertext_len Length of the ciphertext in bytes.
 * @param aad Pointer to the associated data.
 * @param aad_len Length of the associated data in bytes.
 * @param tag Pointer to the 16 byte long authentication tag to verify.
 * @param plaintext Pointer to where to write the decrypted plaintext to. May be the same as ciphertext.
 * @return 0 on success.
 */
typedef int (*fido_aes_gcm_decrypt_t)(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *tag,
    uint8_t *plaintext);

/**
 * @brief Generate ed25519 signature
 *
 * @param signature Pointer to where to write the signature (64 bytes) to.
 * @param secret_key Pointer to the secret key (32 bytes) to sign with.
 * @param message Pointer to the message to sign.
 * @param message_len Length of the message.
 */
typedef void (*fido_ed25519_sign_t)(
    uint8_t *signature,
    const uint8_t *secret_key,
    const uint8_t *message, size_t message_len);

/**
 * @brief Verify ed25519 signature
 *
 * @param signature Pointer to the signature (64 bytes) to verify.
 * @param public_key Pointer to the public key (32 bytes) to verify with.
 * @param message Pointer to the message that was signed.
 * @param message_len Length of the message.
 *
 * @return 0 if the signature is valid.
 */
typedef int (*fido_ed25519_verify_t)(
    const uint8_t *signature,
    const uint8_t *public_key,
    const uint8_t *message, size_t message_len);

/**
 * @brief SHA256 hash
 *
 * @param data Pointer to the data to hash.
 * @param data_len Length of the data.
 * @param hash Pointer to where to write the hash (32 bytes) to.
 */
typedef void (*fido_sha256_t)(
    const uint8_t *data,
    size_t data_len,
    uint8_t *hash
);

/**
 * @brief SHA512 hash
 *
 * @param data Pointer to the data to hash.
 * @param data_len Length of the data.
 * @param hash Pointer to where to write the hash (64 bytes) to.
 */
typedef void (*fido_sha512_t)(
    const uint8_t *data,
    size_t data_len,
    uint8_t *hash
);

/**
 * These are pointers to the cryptographic functions used by this library.
 * They can be set to other functions, for example when the platform supports
 * hardware acceleration for some of the primitives, e.g.
 *
 * fido_ed25510_sign = &my_hardware_accelerated_ed25519_sign;
 *
 * You can define any of the macros
 * NO_SOFTWARE_{AES_GCM_ENCRYPT|AES_GCM_DECRYPT|ED25519_SIGN|ED25519_VERIFY|SHA256|SHA512}
 * to prevent the software implementation of this algorithm to be included in the library.
 * Be aware that AES_GCM_DECRYPT, ED25519_VERIFY and SHA256 are necessary for this library
 * to function correctly. If you don't include the software implementation, replace it with
 * another implementation as described above.
 *
 * Additionally, these functions can be called from other code so they don't
 * have to be reimplemented if needed.
 */
extern fido_aes_gcm_encrypt_t fido_aes_gcm_encrypt;
extern fido_aes_gcm_decrypt_t fido_aes_gcm_decrypt;
extern fido_ed25519_sign_t fido_ed25519_sign;
extern fido_ed25519_verify_t fido_ed25519_verify;
extern fido_sha256_t fido_sha256;
extern fido_sha512_t fido_sha512;
