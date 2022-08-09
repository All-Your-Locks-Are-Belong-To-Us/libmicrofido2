#include "stateless_rp.h"

#include <string.h>

int stateless_assert(fido_dev_t *dev, const char *rp_id, const uint8_t *updater_public_key) {
    int error = FIDO_OK;

    // Open the device. This also gets the device info.
    if ((error = fido_dev_open(dev)) != FIDO_OK) {
        return error;
    }

    // Prepare assertion.
    fido_assert_t assert;
    fido_assert_reset(&assert);
    uint8_t client_data_hash[ASSERTION_CLIENT_DATA_HASH_LEN];

    // Just use a constant client data hash for now.
    memset(client_data_hash, 42, sizeof(client_data_hash));

    fido_assert_set_rp(&assert, rp_id);
    fido_assert_set_extensions(&assert, FIDO_ASSERT_EXTENSION_LARGE_BLOB_KEY);
    fido_assert_set_client_data_hash(&assert, client_data_hash);

    // Perform assertion. It is not verified yet, as this credential public key is unknown at this point in time.
    if ((error = fido_dev_get_assert(dev, &assert)) != FIDO_OK) {
        return error;
    } else if (!assert.reply.has_large_blob_key) {
        return FIDO_ERR_UNSUPPORTED_EXTENSION;
    }

    // Read the per-credential large blob for this credential.
    fido_blob_t blob;
    uint8_t blob_buffer[1024] = {0};
    fido_blob_reset(&blob, blob_buffer, sizeof(blob_buffer));
    if ((error = fido_dev_largeblob_get(dev, assert.reply.large_blob_key, LARGEBLOB_KEY_SIZE, &blob)) != FIDO_OK) {
        return error;
    }

    // blob = credential_public_key (32) | signature(credential_public_key) (64)
    uint8_t *credential_public_key = blob.buffer;
    uint8_t *credential_public_key_signature = blob.buffer + 32;

    // Verify the signature of the credential public key stored in the large blob.
    if((error = fido_ed25519_verify(credential_public_key_signature, updater_public_key, credential_public_key, 32)) != 0) {
        return error;
    }

    // Now, verify the assertion with the public key from the large blob.
    if ((error = fido_assert_verify(&assert, COSE_ALGORITHM_EdDSA, credential_public_key)) != FIDO_OK) {
        return error;
    }

    if ((error = fido_dev_close(dev)) != FIDO_OK) {
        return error;
    }

    return error;
}
