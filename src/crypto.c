#include <aes_gcm.h>
#include <sha256.h>
#include <monocypher-ed25519.h>

#include "crypto.h"

fido_aes_gcm_encrypt_t fido_aes_gcm_encrypt = &aes_gcm_ae;

fido_aes_gcm_decrypt_t fido_aes_gcm_decrypt = &aes_gcm_ad;

void crypto_ed25519_sign_wrapper(uint8_t *signature,
                                 const uint8_t *secret_key,
                                 const uint8_t *message, size_t message_len) {
    crypto_ed25519_sign(signature, secret_key, NULL, message, (int) message_len);
                                
                                 }
fido_ed25519_sign_t fido_ed25519_sign = &crypto_ed25519_sign_wrapper;

fido_ed25519_verify_t fido_ed25519_verify = &crypto_ed25519_check;

fido_sha256_t fido_sha256 = &sha256;

void crypto_sha512_wrapper(const uint8_t *data, size_t data_len,
                           uint8_t *hash) {
    crypto_sha512(hash, data, (int) data_len);
}
fido_sha512_t fido_sha512 = &crypto_sha512_wrapper;
