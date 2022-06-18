/*
 * Copyright (c) 2020-2022 Yubico AB. All rights reserved.
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include "fido.h"
#include "largeblob.h"
#include "utils.h"
#include "error.h"
#include "cbor.h"
#include "dev.h"

#define LARGEBLOB_DIGEST_LENGTH	16
#define LARGEBLOB_NONCE_LENGTH	12
#define LARGEBLOB_TAG_LENGTH	16
#define SHA256_DIGEST_LENGTH    32 // TODO move

// Empty CBOR array (80) followed by LEFT(SHA-256(h'80'), 16)
static const uint8_t fido_largeblob_initial_array[] PROGMEM_MARKER = {0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d, 0x3c};

void fido_blob_reset(fido_blob_t *blob, uint8_t *buffer, size_t buffer_len) {
    blob->buffer = buffer;
    blob->max_length = buffer_len;
    blob->length = 0;
}

static size_t get_chunklen(fido_dev_t *dev) {
    uint64_t maxchunklen;

    if((maxchunklen = dev->maxmsgsize) > SIZE_MAX) {
        maxchunklen = SIZE_MAX;
    }
    if(maxchunklen > FIDO_MAXMSG) {
        maxchunklen = FIDO_MAXMSG;
    }
    maxchunklen = maxchunklen > 64 ? maxchunklen - 64 : 0;
    return (size_t)maxchunklen;
}

/**
 * @brief Builds a CBOR encoded largeblog get request according to the CTAP standard.
 * See https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#largeBlobsRW
 * 
 * @param offset The offset to read in the large blob
 * @param count  The amount of bytes to read from the large blob
 * @param buffer The buffer to write the result to
 * @param buffer_len The length of the buffer
 */
static size_t build_largeblob_get_cbor(size_t offset, size_t count, uint8_t *buffer, size_t buffer_len) {
    cbor_writer_s writer;
    cbor_writer_reset(&writer, buffer, buffer_len);

    cbor_encode_map_start(&writer, 2);

    // Parameter get (0x01)
    cbor_encode_uint(&writer, 0x01);
    cbor_encode_uint(&writer, count);

    // Parameter offset (0x03)
    cbor_encode_uint(&writer, 0x03);
    cbor_encode_uint(&writer, offset);

    if(!cbor_writer_is_ok(&writer)) {
        return 0;
    }
    return writer.length;
}

static bool largeblob_array_digest(uint8_t out[LARGEBLOB_DIGEST_LENGTH], const uint8_t *data, size_t len) {
    uint8_t digest[SHA256_DIGEST_LENGTH];

    if (data == NULL || len == 0) {
        return false;
    }
    // TODO Use SHA256.
    // if (SHA256(data, len, digest) != digest)
    //    return false;
    //}
    memcpy(out, digest, LARGEBLOB_DIGEST_LENGTH);
    return true;
}

static bool largeblob_array_check(fido_blob_t *array) {
    uint8_t expected_hash[LARGEBLOB_DIGEST_LENGTH];

    fido_log_xxd(array->buffer, array->length, __func__);
    if (array->length < sizeof(expected_hash)) {
      fido_log_debug("%s: len %zu", __func__, array->length);
      return false;
    }

    size_t body_len = array->length - sizeof(expected_hash);
    if (!largeblob_array_digest(expected_hash, array->buffer, body_len)) {
      fido_log_debug("%s: largeblob_array_digest", __func__);
      return false;
    }

    // TODO Use timing safe compare.
    // return memcmp(expected_hash, array->buffer + body_len, sizeof(expected_hash)) == 0;
    return true;
}

static int largeblob_get_tx(fido_dev_t *dev, size_t offset, size_t count) {
    // 32 > 1 byte command + 1 byte map header + 1 byte get key + max. 9 byte get value + 1 byte offset key + max. 9 byte offset value
    uint8_t command_buffer[32];
    size_t cbor_len;

    command_buffer[0] = CTAP_CBOR_LARGEBLOB;
    if ((cbor_len = build_largeblob_get_cbor(offset, count, command_buffer + 1, sizeof(command_buffer) - 1)) <= 0) {
        fido_log_debug("%s: cbor encode", __func__);
        return FIDO_ERR_INTERNAL;
    }
    if (fido_tx(dev, CTAP_CMD_CBOR, command_buffer, 1 + cbor_len) != FIDO_OK) {
        fido_log_debug("%s: fido_tx", __func__);
        return FIDO_ERR_TX;
    }

    return FIDO_OK;
}

static int parse_largeblob_reply(const cb0r_t key, const cb0r_t value, void *arg) {
    fido_blob_t *chunk = (fido_blob_t*) arg;

    // We are just interested in the config (0x01) parameter.
    // See response in https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#largeBlobsRW
    if (key->type != CB0R_INT || key->value != 0x01) {
        return FIDO_OK;
    } else if (value->type != CB0R_BYTE) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    } else if (value->length > chunk->max_length) {
        return FIDO_ERR_INTERNAL;
    }
    memcpy(chunk->buffer, value->start + value->header, value->length);
    chunk->length = value->length;
    return FIDO_OK;
}

static int largeblob_get_rx(fido_dev_t *dev, fido_blob_t *chunk) {
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
    if (!cb0r_read(msg+1, msglen-1, &map) || map.type != CB0R_MAP) {
        return  FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    return cbor_iter_map(&map, &parse_largeblob_reply, chunk);
}

int fido_dev_largeblob_get_array(fido_dev_t *dev, fido_blob_t *largeblob_array) {
    fido_blob_t chunk;

    // Make sure to start writing at the start of the array buffer.
    largeblob_array->length = 0;

    size_t get_len;
    int r;

    if ((get_len = get_chunklen(dev)) == 0) {
        return FIDO_ERR_INVALID_ARGUMENT;
    }

    do {
        // Get the next chunk. Writes directly to the buffer of the largeblob_array.
        fido_blob_reset(&chunk, largeblob_array->buffer + largeblob_array->length,
                                largeblob_array->max_length - largeblob_array->length);

        if ((r = largeblob_get_tx(dev, largeblob_array->length, get_len)) != FIDO_OK ||
            (r = largeblob_get_rx(dev, &chunk)) != FIDO_OK) {
                fido_log_debug("%s: largeblob_get_wait %zu/%zu", __func__, largeblob_array->length, get_len);
                return r;
        }
        // Receiving the chunk of data was successful.
        // The data was automatically appended to largeblob_array, because chunk uses the same buffer.
        largeblob_array->length += chunk.length;
    } while (chunk.length == get_len);

    // Verify the checksum.
    if (!largeblob_array_check(largeblob_array)) {
        // If the checksum is not correct, use an empty array (+checksum) instead.
        if (sizeof(fido_largeblob_initial_array) < largeblob_array->max_length) {
            return FIDO_ERR_INTERNAL;
        }
        memcpy(largeblob_array->buffer, fido_largeblob_initial_array, sizeof(fido_largeblob_initial_array));
        largeblob_array->length = sizeof(fido_largeblob_initial_array);
    }
    return FIDO_OK;
}
