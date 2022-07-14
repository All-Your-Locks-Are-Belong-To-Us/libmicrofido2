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

        if(assert->opt & FIDO_ASSERT_OPTION_UP){
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
                false
            );
        }
        if(assert->opt & FIDO_ASSERT_OPTION_UV){
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

static int cbor_assert_decode_auth_data(const cb0r_t auth_data, fido_assert_reply_t *ca) {
    if (!cbor_bytestring_is_definite(auth_data)) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }
    if(cb0r_vlen(auth_data) > sizeof(ca->auth_data)) {
        return FIDO_ERR_BUFFER_TOO_SHORT;
    }
    memcpy(ca->auth_data, cb0r_value(auth_data), cb0r_vlen(auth_data));
    return FIDO_OK;
}

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
 * @brief Parse an entry of the authenticatorGetInfo CBOR map.
 *
 * @param key The cb0r element representing the map key
 * @param value The cb0r element representing the map value
 * @param arg User-passed argument (here: CBOR info).
 * @return int FIDO_OK if entry could be parsed.
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

// TODO: function to set rpid
// TODO: function to set client data (and compute hash)

static int fido_dev_get_assert_tx(
    fido_dev_t *dev,
    fido_assert_t *assert,
    const es256_pk_t *pk,
    const fido_blob_t *ecdh
) {
    // 32 > 1 byte command + 1 byte map header + 1 byte get key + max. 9 byte get value + 1 byte offset key + max. 9 byte offset value
    int command_buffer_len = 1 + 1 + 1 + assert->rp_id.len + 1 + sizeof(assert->cdh) + 32;
    uint8_t command_buffer[command_buffer_len];
    int cbor_len;

    command_buffer[0] = CTAP_CBOR_ASSERT;
    if ((cbor_len = build_get_assert_cbor(assert, command_buffer + 1, sizeof(command_buffer) - 1)) <= 0) {
        fido_log_debug("%s: cbor encode", __func__);
        return FIDO_ERR_INTERNAL;
    }
    if (fido_tx(dev, CTAP_CMD_CBOR, command_buffer, 1 + cbor_len) != FIDO_OK) {
        fido_log_debug("%s: fido_tx", __func__);
        return FIDO_ERR_TX;
    }

    return FIDO_OK;
}

static int fido_dev_get_assert_rx(fido_dev_t *dev, fido_assert_t *assert, fido_assert_reply_t *ca) {
    uint8_t msg[dev->maxmsgsize];
    int msglen;

    if ((msglen = fido_rx(dev, CTAP_CMD_CBOR, msg, sizeof(msg))) < 0) {
        fido_log_debug("%s: fido_rx", __func__);
        return FIDO_ERR_RX;
    }

    if (msg[0] != FIDO_OK) {
        return msg[0];
    }

    cb0r_s map;
    if (!cb0r_read(msg + 1, msglen - 1, &map) || map.type != CB0R_MAP) {
        return  FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    return cbor_iter_map(&map, &parse_get_assert_reply_entry, ca);
}

static int fido_dev_get_assert_wait(fido_dev_t *dev, fido_assert_t *assert,
    const es256_pk_t *pk, const fido_blob_t *ecdh, fido_assert_reply_t *ca
) {
    int r;

    if ((r = fido_dev_get_assert_tx(dev, assert, pk, ecdh)) != FIDO_OK ||
        (r = fido_dev_get_assert_rx(dev, assert, ca)) != FIDO_OK)
        return (r);

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

int fido_dev_get_assert(fido_dev_t *dev, fido_assert_t *assert) {
    fido_blob_t    *ecdh    = NULL;
    es256_pk_t     *pk      = NULL;
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
    r = fido_dev_get_assert_wait(dev, assert, pk, ecdh, &assert->reply);

    return r;
}

void fido_assert_set_rp(fido_assert_t *assert, const char* id) {
    const size_t len = strlen(id);
    assert->rp_id.len = len;
    assert->rp_id.ptr = (uint8_t*)id;
}

void fido_assert_set_client_data_hash(fido_assert_t *assert, const uint8_t hash[SHA256_BLOCK_SIZE]) {
    memcpy(assert->cdh, hash, sizeof(assert->cdh));
}

void fido_assert_set_options(fido_assert_t *assert, const fido_assert_opt_t options) {
    assert->opt = options;
}

void fido_assert_set_extensions(fido_assert_t *assert, const fido_assert_ext_t extensions) {
    assert->ext = extensions;
}
