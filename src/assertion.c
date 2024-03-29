/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include "fido.h"
#include "cbor.h"
#include "utils.h"

#define CBOR_ASSERT_WRITER_STATUS_OK(writer, function, ...) { function(&writer, __VA_ARGS__); if (!cbor_writer_is_ok(&writer)) { return FIDO_ERR_BUFFER_TOO_SHORT; } }
#define GET_ASSERTION_MAX_COMMAND_BUFFER_LEN 256
#define GET_ASSERTION_COMMAND_BUFFER_LEN_INCREMENT 32

/**
 * @brief Encode assertion request into CBOR.
 *
 * @param assert The assertion request to encode.
 * @param buffer A pointer to the buffer to store the CBOR-encoded assertion request into.
 * @param buffer_len The length of the buffer.
 * @return int A negative value (FIDO_ERR_*) when encoding failed, otherwise the length of the encoded assertion request.
 */
static int build_get_assert_cbor(fido_assert_t *assert, uint8_t *buffer, size_t buffer_len) {
    cbor_writer_s writer;
    cbor_writer_reset(&writer, buffer, buffer_len);

    int map_elements = 2;
    // Count the number of extensions and options.
    int ext_set_count = __builtin_popcount(assert->ext);
    int opt_set_count = __builtin_popcount(assert->opt);

    if(ext_set_count != 0){
        map_elements++;
    }
    if(opt_set_count != 0){
        map_elements++;
    }

    CBOR_ASSERT_WRITER_STATUS_OK(writer, cbor_encode_map_start, map_elements);

    // Parameter rpId (0x01)
    CBOR_ASSERT_WRITER_STATUS_OK(writer, cbor_encode_uint, 0x01);
    CBOR_ASSERT_WRITER_STATUS_OK(writer, cbor_encode_string, assert->rp_id.ptr, assert->rp_id.len);

    // Parameter clientDataHash (0x02)
    CBOR_ASSERT_WRITER_STATUS_OK(writer, cbor_encode_uint, 0x02);
    CBOR_ASSERT_WRITER_STATUS_OK(writer, cbor_encode_bytestring, assert->cdh, sizeof(assert->cdh));

    if(ext_set_count != 0){
        // Parameter extensions (0x04)
        CBOR_ASSERT_WRITER_STATUS_OK(writer, cbor_encode_uint, 0x04);
        CBOR_ASSERT_WRITER_STATUS_OK(writer, cbor_encode_map_start, ext_set_count);

        if(assert->ext & FIDO_ASSERT_EXTENSION_LARGE_BLOB_KEY){
            const unsigned char fido_extension_large_blob_key[] = "largeBlobKey";
            CBOR_ASSERT_WRITER_STATUS_OK(
                writer,
                cbor_encode_string,
                fido_extension_large_blob_key,
                sizeof(fido_extension_large_blob_key) - 1
            );
            CBOR_ASSERT_WRITER_STATUS_OK(
                writer,
                cbor_encode_boolean,
                true
            );
        }
    }

    if(opt_set_count != 0){
        // Parameter options (0x05)
        cbor_encode_uint(&writer, 0x05);
        cbor_encode_map_start(&writer, opt_set_count);

        if (assert->opt & FIDO_ASSERT_OPTION_UP) {
            const unsigned char fido_option_up[] = "up";
            CBOR_ASSERT_WRITER_STATUS_OK(
                writer,
                cbor_encode_string,
                fido_option_up,
                sizeof(fido_option_up) - 1
            );
            CBOR_ASSERT_WRITER_STATUS_OK(
                writer,
                cbor_encode_boolean,
                true
            );
        }
        if (assert->opt & FIDO_ASSERT_OPTION_UV) {
            const unsigned char fido_option_uv[] = "uv";
            CBOR_ASSERT_WRITER_STATUS_OK(
                writer,
                cbor_encode_string,
                fido_option_uv,
                sizeof(fido_option_uv) - 1
            );
            CBOR_ASSERT_WRITER_STATUS_OK(
                writer,
                cbor_encode_boolean,
                true
            );
        }
    }

    return writer.length;
}

static const uint8_t KEY_TYPE[] PROGMEM_MARKER = "type";
static const uint8_t KEY_TYPE_PUBLIC_KEY[] PROGMEM_MARKER = "public-key";
static const uint8_t KEY_ID[] PROGMEM_MARKER = "id";

/**
 * @brief CBOR decode the credential's data such as its type and ID.
 *        See https://w3c.github.io/webauthn/#dictdef-publickeycredentialdescriptor
 *
 * @param key The CBOR key.
 * @param assert The CBOR value.
 * @param arg The assert reply argument to store the parsed data to.
 * @return int FIDO_OK if the operation was successful.
 */
static int cbor_assert_decode_credential(const cb0r_t key, const cb0r_t value, void *arg) {
    if (!cbor_utf8string_is_definite(key)) {
        // Just ignore the entry according to https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#message-encoding.
        return FIDO_OK;
    }

    fido_assert_reply_t *ca = (fido_assert_reply_t*)arg;

    if (CBOR_STR_MEMCMP(key, KEY_TYPE)) {
        if (!cbor_utf8string_is_definite(value)) {
            return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
        }
        if (CBOR_STR_MEMCMP(value, KEY_TYPE_PUBLIC_KEY)) {
            ca->credential.type |= FIDO_CREDENTIAL_TYPE_PUBLIC_KEY;
        }
    } else if (CBOR_STR_MEMCMP(key, KEY_ID)) {
        if (!cbor_bytestring_is_definite(value)) {
            return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
        }
        if (cb0r_vlen(value) > sizeof(ca->credential.id)) {
            return FIDO_ERR_BUFFER_TOO_SHORT;
        }
        memcpy(&ca->credential.id, cb0r_value(value), cb0r_vlen(value));
        ca->credential.id_length = cb0r_vlen(value);
    }

    // "transports" is not supported. :)
    return FIDO_OK;
}

/**
 * @brief CBOR decode the auth data such as the RP ID hash and signature count.
 *        See https://www.w3.org/TR/webauthn-2/#authenticator-data
 *
 * @param auth_data_raw The raw auth data.
 * @param ca The reply entry to store the parsed data to.
 * @return int FIDO_OK if the operation was successful.
 */
static int cbor_assert_decode_auth_data_inner(void* auth_data_raw, fido_assert_reply_t *ca) {
    uint8_t* auth_data_bytes = (uint8_t*) auth_data_raw;

    // 32 byte rpIdHash
    memcpy(ca->auth_data.rp_id_hash, auth_data_bytes, ASSERTION_AUTH_DATA_RPID_HASH_LEN);
    auth_data_bytes += ASSERTION_AUTH_DATA_RPID_HASH_LEN;

    // 1 byte flags
    ca->auth_data.flags = *auth_data_bytes;
    auth_data_bytes += 1;

    // 4 byte signature count
    ca->auth_data.sign_count = be32toh(*((uint32_t*)auth_data_bytes));
    auth_data_bytes += 4;

    // attested credential data and extension unsupported for now.

    return FIDO_OK;
}

/**
 * @brief Wrapper to decode the CBOR encoded authentication data.
 *
 * @param auth_data The CBOR encoded authentication data.
 * @param ca The reply entry to store the parsed data to.
 * @return int FIDO_OK if the operation was successful.
 */
static int cbor_assert_decode_auth_data(const cb0r_t auth_data, fido_assert_reply_t *ca) {
    if (!cbor_bytestring_is_definite(auth_data)) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }
    size_t auth_data_len = cb0r_vlen(auth_data);
    if(auth_data_len > sizeof(ca->auth_data)) {
        return FIDO_ERR_BUFFER_TOO_SHORT;
    }
    memcpy(ca->auth_data_raw, cb0r_value(auth_data), auth_data_len);
    ca->auth_data_length = auth_data_len;

    return cbor_assert_decode_auth_data_inner(ca->auth_data_raw, ca);
}

/**
 * @brief Decode the assertion signature from the CBOR entry.
 *
 * @param signature The CBOR encoded signature data.
 * @param ca The reply entry to store the parsed data to.
 * @return int FIDO_OK if the operation was successful.
 */
static int cbor_assert_decode_signature(const cb0r_t signature, fido_assert_reply_t *ca) {
    if (!cbor_bytestring_is_definite(signature)) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    if(cb0r_vlen(signature) > sizeof(ca->signature)) {
        return FIDO_ERR_BUFFER_TOO_SHORT;
    }
    memcpy(ca->signature, cb0r_value(signature), cb0r_vlen(signature));
    return FIDO_OK;
}

/**
 * @brief Decode the large blob key from the CBOR entry.
 *
 * @param large_blob_key The CBOR encoded signature data.
 * @param ca The reply entry to store the parsed data to.
 * @return int FIDO_OK if the operation was successful.
 */
static int cbor_assert_decode_large_blob_key(const cb0r_t large_blob_key, fido_assert_reply_t *ca) {
    if (!cbor_bytestring_is_definite(large_blob_key)) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    if(cb0r_vlen(large_blob_key) > sizeof(ca->large_blob_key)) {
        return FIDO_ERR_BUFFER_TOO_SHORT;
    }
    memcpy(ca->large_blob_key, cb0r_value(large_blob_key), cb0r_vlen(large_blob_key));
    ca->has_large_blob_key = true;
    return FIDO_OK;
}

/**
 * @brief Parse an entry of the authenticatorGetAssertion CBOR map.
 *
 * @param key The cb0r element representing the map key
 * @param value The cb0r element representing the map value
 * @param arg User-passed argument (here: assertion reply).
 * @return int FIDO_OK if the entry could be parsed.
 */
static int parse_get_assert_reply_entry(const cb0r_t key, const cb0r_t value, void *arg) {
    if (key->type != CB0R_INT || key->value > UINT8_MAX) {
        // Just ignore the entry according to https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#message-encoding.
        return FIDO_OK;
    }

    fido_assert_reply_t *ca = (fido_assert_reply_t*)arg;

    switch (key->value) {
        case 1: // credential
            return cbor_iter_map(value, cbor_assert_decode_credential, ca);
        case 2: // auth data
            return cbor_assert_decode_auth_data(value, ca);
        case 3: // signature
            return cbor_assert_decode_signature(value, ca);
        case 4: // user --ignore for now
            return FIDO_OK;
        case 5: // numberOfCredentials --ignore for now
            return FIDO_OK;
        case 6: // userSelected --ignore for now
            return FIDO_OK;
        case 7: // large blob key
            return cbor_assert_decode_large_blob_key(value, ca);
        default: // ignore
            fido_log_debug("%s: cbor type", __func__);
            return FIDO_OK;
    }
}

/**
 * @brief Transmit the request data to the authenticator.
 *
 * @param dev The device to communicate to.
 * @param assert The assertion request data.
 * @return int FIDO_OK if the operation was successful.
 */
static int fido_dev_get_assert_tx(
    fido_dev_t *dev,
    fido_assert_t *assert
) {
    // We do not know the size of the command buffer, yet, as extensions can have different length.
    // So we start with a sane value and try our luck until the buffer is large enough.

    // 1 byte command + 1 byte map header + maximum of 4 supported keys, 1 byte each + rpid (incl. max two bytes of cbor prefix) +
    // client data hash (incl 2 bytes cbor prefix) + 9 bytes for options, 32 bytes for extensions.
    int command_buffer_len = 1 + 1 + 4 + (assert->rp_id.len + 2) + sizeof(assert->cdh) + 9 + 32;
    int cbor_len;
    int ret;

    // Test the required length.
    {
        uint8_t command_buffer[command_buffer_len];
        while (
            command_buffer_len < GET_ASSERTION_MAX_COMMAND_BUFFER_LEN &&
            (cbor_len = build_get_assert_cbor(assert, command_buffer + 1, sizeof(command_buffer) - 1)) == FIDO_ERR_BUFFER_TOO_SHORT
        ) {
            command_buffer_len += GET_ASSERTION_COMMAND_BUFFER_LEN_INCREMENT;
        }
    }

    uint8_t command_buffer[command_buffer_len];

    command_buffer[0] = CTAP_CBOR_ASSERT;
    if ((cbor_len = build_get_assert_cbor(assert, command_buffer + 1, sizeof(command_buffer) - 1)) <= 0) {
        fido_log_debug("%s: cbor encode", __func__);
        ret = FIDO_ERR_INTERNAL;
        goto out;
    }
    if (fido_tx(dev, CTAP_CMD_CBOR, command_buffer, 1 + cbor_len) != FIDO_OK) {
        fido_log_debug("%s: fido_tx", __func__);
        ret = FIDO_ERR_TX;
        goto out;
    }

    ret = FIDO_OK;
out:
    memset(command_buffer, 0, command_buffer_len);
    return ret;
}

/**
 * @brief Receive the response data from the authenticator and parse the authenticator's response into the reply.
 *
 * @param dev The device to communicate to.
 * @param assert The assertion request data.
 * @param reply A pointer to the structure to store the parsed data to.
 * @return int FIDO_OK if the operation was successful.
 */
static int fido_dev_get_assert_rx(
    fido_dev_t *dev,
    fido_assert_t *assert,
    fido_assert_reply_t *reply
) {
    uint8_t msg[dev->maxmsgsize];
    int msglen;
    int ret;

    if ((msglen = fido_rx(dev, CTAP_CMD_CBOR, msg, sizeof(msg))) < 0) {
        fido_log_debug("%s: fido_rx", __func__);
        ret = FIDO_ERR_RX;
        goto out;
    }

    if (msg[0] != FIDO_OK) {
        ret = msg[0];
        goto out;
    }

    cb0r_s map;
    if (!cb0r_read(msg + 1, msglen - 1, &map) || map.type != CB0R_MAP) {
        ret = FIDO_ERR_CBOR_UNEXPECTED_TYPE;
        goto out;
    }

    ret = cbor_iter_map(&map, &parse_get_assert_reply_entry, reply);
out:
    memset(msg, 0, dev->maxmsgsize);
    return ret;
}

/**
 * @brief Perform the assertion transmission and receival and wait for their completion.
 *
 * @param dev The device to communicate to.
 * @param assert The assertion request data.
 * @param reply A pointer to the structure to store the parsed data to.
 * @return int 0, if the check is successful
 */
static int fido_dev_get_assert_wait(
    fido_dev_t *dev,
    fido_assert_t *assert,
    fido_assert_reply_t *reply
) {
    int r;

    if ((r = fido_dev_get_assert_tx(dev, assert)) != FIDO_OK ||
        (r = fido_dev_get_assert_rx(dev, assert, reply)) != FIDO_OK)
        return r;

    return FIDO_OK;
}

/**
 * @brief Reset an assertion reply to a known state.
 *
 * @param reply A pointer to the reply to reset.
 */
static inline void fido_assert_reply_reset(fido_assert_reply_t *reply) {
    memset(reply, 0, sizeof(*reply));
}

void fido_assert_reset(fido_assert_t *assert) {
    memset(assert, 0, sizeof(*assert));
}

int fido_dev_get_assert(fido_dev_t *dev, fido_assert_t *assert) {
    int             r;

    if (assert->rp_id.ptr == NULL) {
        fido_log_debug(
            "%s: rp_id=%p",
            __func__,
            (void *)assert->rp_id,
        );
        return FIDO_ERR_INVALID_ARGUMENT;
    }

    if (fido_dev_is_fido(dev) == false) {
        return FIDO_ERR_INVALID_ARGUMENT;
    }

    fido_assert_reply_reset(&assert->reply);
    r = fido_dev_get_assert_wait(dev, assert, &assert->reply);

    return r;
}

void fido_assert_set_rp(fido_assert_t *assert, const char* id) {
    const size_t len = strlen(id);
    assert->rp_id.len = len;
    assert->rp_id.ptr = (uint8_t*)id;
}

void fido_assert_set_client_data_hash(fido_assert_t *assert, const uint8_t hash[ASSERTION_CLIENT_DATA_HASH_LEN]) {
    memcpy(assert->cdh, hash, sizeof(assert->cdh));
}

void fido_assert_set_client_data(fido_assert_t *assert, const uint8_t *client_data, const size_t client_data_len) {
    fido_sha256(client_data, client_data_len, assert->cdh);
}


void fido_assert_set_options(fido_assert_t *assert, const fido_assert_opt_t options) {
    assert->opt = options;
}

void fido_assert_set_extensions(fido_assert_t *assert, const fido_assert_ext_t extensions) {
    assert->ext = extensions;
}

/**
 * @brief Check, that user presence or verification are performed successfully, when desired.
 *
 * @param auth_data_flags The flags retrieved in the auth_data from the authenticator.
 * @param assert_opt The user defined options.
 * @return int 0, if the check is successful
 */
static int fido_check_flags(fido_assert_auth_data_flags_t auth_data_flags, fido_assert_opt_t assert_opt) {
    int up = assert_opt & FIDO_ASSERT_OPTION_UP;
    int uv = assert_opt & FIDO_ASSERT_OPTION_UV;
    if (up == FIDO_ASSERT_OPTION_UP &&
        ((auth_data_flags & FIDO_AUTH_DATA_FLAGS_UP) == FIDO_AUTH_DATA_FLAGS_UP) == 0) {
        fido_log_debug("%s: CTAP_AUTHDATA_USER_PRESENT", __func__);
        return -1; /* user not present */
    }

    if (uv == FIDO_ASSERT_OPTION_UV &&
        ((auth_data_flags & FIDO_AUTH_DATA_FLAGS_UV) == FIDO_AUTH_DATA_FLAGS_UV) == 0) {
        fido_log_debug("%s: CTAP_AUTHDATA_USER_VERIFIED", __func__);
        return -1; /* user not verified */
    }

    return 0;
}

/**
 * @brief Ensure that the hash of the relying party concurs with the expected one.
 *
 * @param rp_id The expected relying party id.
 * @param obtained_hash The hash of the relying party id obtained from the authenticator.
 * @return int 0, if the hash is correct
 */
static int fido_check_rp_id(const fido_assert_blob_t *rp_id, const uint8_t *obtained_hash) {
    uint8_t expected_hash[ASSERTION_AUTH_DATA_RPID_HASH_LEN] = {0};
    if(fido_sha256 == NULL) {
        return FIDO_ERR_INTERNAL;
    }
    fido_sha256(rp_id->ptr, rp_id->len, expected_hash);

    int res = memcmp(expected_hash, obtained_hash, SHA256_BLOCK_SIZE);
    memset(expected_hash, 0, ASSERTION_AUTH_DATA_RPID_HASH_LEN);
    return res;
}

/**
 * @brief Create the data that was signed by the authenticator.
 *
 * @param cose_alg The COSE algorithm identifier.
 * @param buf A buffer to place the result in.
 * @param client_data_hash The client data hash.
 * @param auth_data The raw auth_data bytes.
 * @param auth_data_length The length of the auth_data.
 * @return int The length written in the buffer, or an error < 0
 */
static int fido_get_signed_hash(
    int cose_alg,
    uint8_t* buf,
    const uint8_t* client_data_hash,
    const uint8_t* auth_data,
    size_t auth_data_length
) {
    if((auth_data_length + ASSERTION_CLIENT_DATA_HASH_LEN) > ASSERTION_PRE_IMAGE_LENGTH) {
        return -1;
    }
    switch(cose_alg) {
        case COSE_ALGORITHM_EdDSA: {
            memcpy(buf, auth_data, auth_data_length);
            memcpy(buf + auth_data_length, client_data_hash, ASSERTION_CLIENT_DATA_HASH_LEN);
            return auth_data_length + ASSERTION_CLIENT_DATA_HASH_LEN;
        }
        default:
            fido_log_debug(
                "%s: unsupported cose_alg %d",
                __func__,
                cose_alg
            );
            return -1;
    }
}

int fido_assert_verify(const fido_assert_t *assert, const int cose_alg, const uint8_t *pk) {
    int r;
    uint8_t hash_buf[ASSERTION_PRE_IMAGE_LENGTH] = { 0 }; // Authdata + Client data hash

    if(pk == NULL) {
        return FIDO_ERR_INVALID_ARGUMENT;
    }

    const fido_assert_reply_t *reply = &(assert->reply);

    /* do we have everything we need? */
    if (assert->rp_id.ptr == NULL) {
        return FIDO_ERR_INVALID_ARGUMENT;
    }

    if (fido_check_flags(reply->auth_data.flags, assert->opt) < 0) {
        fido_log_debug("%s: fido_check_flags", __func__);
        return FIDO_ERR_INVALID_PARAM;
    }

    // TODO: Extensions not supported for now.

    if (fido_check_rp_id(&(assert->rp_id), reply->auth_data.rp_id_hash) != 0) {
        fido_log_debug("%s: fido_check_rp_id", __func__);
        return FIDO_ERR_INVALID_PARAM;
    }

    int hash_buf_len;
    if ((hash_buf_len = fido_get_signed_hash(cose_alg, hash_buf, assert->cdh,
        reply->auth_data_raw, reply->auth_data_length)) < 0) {
        fido_log_debug("%s: fido_get_signed_hash", __func__);
        r =  FIDO_ERR_INTERNAL;
        goto out;
    }

    int ok = -1;
    switch(cose_alg) {
        case COSE_ALGORITHM_EdDSA: {
            if(fido_ed25519_verify == NULL) {
                r = FIDO_ERR_INTERNAL;
                goto out;
            }

            ok = fido_ed25519_verify(reply->signature, pk, hash_buf, hash_buf_len);
            break;
        }
        default:
            fido_log_debug(
                "%s: unsupported cose_alg %d",
                __func__,
                cose_alg
            );
            r = FIDO_ERR_UNSUPPORTED_OPTION;
            goto out;
    }

    if (ok < 0) {
        r = FIDO_ERR_INVALID_SIG;
    } else {
        r = FIDO_OK;
    }

out:
    memset(hash_buf, 0, sizeof(hash_buf));
    return r;
}
