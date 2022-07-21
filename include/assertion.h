/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#pragma once

#include "dev.h"
#include "largeblob.h"
#include "sha256.h" // TODO: Use Monocypher with abstraction

// ed25519 signatures are 512 bits long
// We do not support other (longer) signatures for now.
#define ASSERTION_SIGNATURE_LENGTH 64

// The standard says 1023, see https://github.com/w3c/webauthn/pull/1664.
// see https://github.com/solokeys/fido-authenticator/pull/8
// We define this as our maximum in order to reduce stack usage.
#define ASSERTION_MAX_KEY_HANDLE_LENGTH 255

// This is not defined by the standard.
// However, we define this as our limit.
#define ASSERTION_AUTH_DATA_LENGTH 128
#define ASSERTION_AUTH_DATA_RPID_HASH_LEN 32

// A SHA256 hash.
#define ASSERTION_CLIENT_DATA_HASH_LEN 32

#define ASSERTION_PRE_IMAGE_LENGTH ASSERTION_AUTH_DATA_LENGTH + SHA256_DIGEST_LENGTH

typedef void es256_pk_t;

typedef struct fido_assert_blob {
    uint8_t const  *ptr;
    size_t          len;
} fido_assert_blob_t;

#define FIDO_ASSERT_EXTENSION_LARGE_BLOB_KEY        FIDO_EXT_LARGEBLOB_KEY
typedef uint8_t fido_assert_ext_t;

#define FIDO_ASSERT_OPTION_UP                       BITFIELD(0)
#define FIDO_ASSERT_OPTION_UV                       BITFIELD(1)
typedef uint8_t fido_assert_opt_t;

#define FIDO_CREDENTIAL_TYPE_PUBLIC_KEY             BITFIELD(0)
typedef uint8_t fido_cbor_credential_type_t;

typedef struct fido_cbor_credential {
    fido_cbor_credential_type_t type;               // credential type
    uint8_t id[ASSERTION_MAX_KEY_HANDLE_LENGTH];    // credential id
    uint8_t id_length;                              // The length of the credential id.
} fido_cbor_credential_t;

// User Presence
#define FIDO_AUTH_DATA_FLAGS_UP         BITFIELD(0)
// User Verified
#define FIDO_AUTH_DATA_FLAGS_UV         BITFIELD(2)
// Attested Credential Data
#define FIDO_AUTH_DATA_FLAGS_AT         BITFIELD(6)
// Extension Data Included
#define FIDO_AUTH_DATA_FLAGS_ED         BITFIELD(7)
typedef uint8_t fido_assert_auth_data_flags_t;

// See https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
typedef struct fido_assert_auth_data {
    uint8_t                           rp_id_hash[ASSERTION_AUTH_DATA_RPID_HASH_LEN];
    fido_assert_auth_data_flags_t     flags;
    uint32_t                          sign_count;
    // TODO: extensions and attestedCredentialData not supported for now.
} fido_assert_auth_data_t;

// See https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-getAssert-authnr-alg
typedef struct fido_assert_reply {
    fido_cbor_credential_t  credential;
    uint8_t                 auth_data_raw[ASSERTION_AUTH_DATA_LENGTH];
    int                     auth_data_length;
    fido_assert_auth_data_t auth_data;
    uint8_t                 signature[ASSERTION_SIGNATURE_LENGTH];
    uint8_t                 large_blob_key[LARGEBLOB_KEY_SIZE];
    bool                    has_large_blob_key;
} fido_assert_reply_t;


typedef struct fido_assert {
    fido_assert_blob_t          rp_id;                                  // relying party id
    uint8_t                     cdh[ASSERTION_CLIENT_DATA_HASH_LEN];    // client data hash
    fido_assert_opt_t           opt;                                    // user presence & user verification
    fido_assert_ext_t           ext;                                    // enabled extensions
    fido_assert_reply_t         reply;                                  // The parsed reply. Only one credential is supported!
} fido_assert_t;

/**
 * @brief Reset an assertion request to a known state.
 * 
 * @param assert A pointer to the assertion data structure to reset.
 */
void fido_assert_reset(fido_assert_t *assert);

/**
 * @brief Get assertion from device.
 *
 * Note that only one assertion statement is supported (numberOfCredentials > 1 is ignored).
 *
 * @param dev The device to read from.
 * @param assert Options for the assertion.
 * @return success or failure
 */
int fido_dev_get_assert(fido_dev_t *dev, fido_assert_t *assert);

/**
 * @brief Set the relying party ID for an assertion.
 *
 * **Warning:** Do not change the string data until having called `fido_dev_get_assert`.
 *
 * @param assert A pointer to an assertion request to set the relying party on.
 * @param id The relying party ID as string (NULL-terminated).
 */
void fido_assert_set_rp(fido_assert_t *assert, const char* id);

/**
 * @brief Set the client data hash for an assertion.
 *
 * Note: This should be non-predictable.
 *
 * @param assert A pointer to an assertion request to set the client data hash on.
 * @param hash The SHA256 hash of the client data.
 */
void fido_assert_set_client_data_hash(fido_assert_t *assert, const uint8_t hash[ASSERTION_CLIENT_DATA_HASH_LEN]);

/**
 * @brief Set the options field for an assertion.
 *
 * @param assert A pointer to an assertion request to set the options on.
 * @param options The options, see FIDO_ASSERT_OPTION_*.
 */
void fido_assert_set_options(fido_assert_t *assert, const fido_assert_opt_t options);

/**
 * @brief Set the extensions field for an assertion.
 *
 * @param assert A pointer to an assertion request to set the extensions on.
 * @param extensions The extensions, see FIDO_ASSERT_EXTENSION_*.
 */
void fido_assert_set_extensions(fido_assert_t *assert, const fido_assert_ext_t extensions);

/**
 * @brief Verify an assertion.
 * 
 * @param assert A pointer to an assertion request/reply struct.
 * @param cose_alg A COSE algorithm identifier.
 * @param pk The key to verify the signature.
 * @return int 
 */
int fido_assert_verify(const fido_assert_t *assert, int cose_alg, const void *pk);
