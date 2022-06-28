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
#include <aes_gcm.h>
#include <sha256.h>
#include <stdint.h>
#include <string.h>

#define LARGEBLOB_DIGEST_LENGTH             16
#define LARGEBLOB_NONCE_LENGTH              12
#define LARGEBLOB_TAG_LENGTH                16
#define LARGEBLOB_DIGEST_SIZE               SHA256_BLOCK_SIZE
#define LARGEBLOB_DIGEST_COMPARISON_SIZE    16

// Empty CBOR array (80) followed by LEFT(SHA-256(h'80'), 16)
static const uint8_t fido_largeblob_initial_array[] PROGMEM_MARKER = {0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d, 0x3c};

void fido_blob_reset(fido_blob_t *blob, uint8_t *buffer, size_t buffer_len) {
    blob->buffer = buffer;
    blob->max_length = buffer_len;
    blob->length = 0;
}

/**
 * @brief Return the length of a chunk when reading the large blob.
 *        Repeated requests to the large blob are used to read out the desired
 *        amount of data in chunks.
 *
 * @param dev The device to get the chunk length for.
 * @return size_t The chunk length.
 */
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
 * @brief Builds a CBOR encoded largeblob get request according to the CTAP2 standard.
 * See https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#largeBlobsRW
 *
 * @param offset The offset to read in the large blob.
 * @param count  The amount of bytes to read from the large blob.
 * @param buffer The buffer to write the result to.
 * @param buffer_len The length of the buffer.
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

/**
 * @brief Calculate the digest of a large-blob array and check if it matches the expected digest.
 *
 * @param out A buffer to write the digest to.
 * @param data A pointer to the largeblob array buffer.
* @param data The length of the largeblob array buffer.
 * @return bool True if the given largeblob array digest matches the calculated digest.
 */
static bool largeblob_array_digest(uint8_t out[LARGEBLOB_DIGEST_SIZE], const uint8_t *data, size_t len) {
    uint8_t digest[SHA256_DIGEST_SIZE];

    if (data == NULL || len == 0) {
        return false;
    }
    sha256(data, len, out);
    return true;
}

/**
 * @brief Check if a largeblob array contains valid header fields and digest.
 *
 * @param array A pointer to a largeblob array.
 * @return bool true, if the length has been set correct and the digest matches.
 */
static bool largeblob_array_check(fido_blob_t *array) {
    uint8_t expected_hash[LARGEBLOB_DIGEST_SIZE];

    fido_log_xxd(array->buffer, array->length, __func__);
    if (array->length < sizeof(expected_hash)) {
      fido_log_debug("%s: len %zu", __func__, array->length);
      return false;
    }

    size_t body_len = array->length - LARGEBLOB_DIGEST_COMPARISON_SIZE;
    if (!largeblob_array_digest(expected_hash, array->buffer, body_len)) {
      fido_log_debug("%s: largeblob_array_digest", __func__);
      return false;
    }

    return memcmp(expected_hash, array->buffer + body_len, LARGEBLOB_DIGEST_COMPARISON_SIZE) == 0;
}

/**
 * @brief Transmit a CTAP command to read from the large blob.
 *
 * @param dev The device to read the large blob from.
 * @param offset The offset in the large blob to start reading from.
 * @param count The amount of bytes to read.
 * @return int FIDO_OK when the operation was successful.
 */
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

/**
 * @brief Parse the response of authenticatorLargeBlob.
 *
 * @param key The key of the map entry.
 * @param value The value of the map entry.
 * @param arg The fido_blob_t to write the chunk from the response to.
 * @return int FIDO_OK if parsing was successful.
 */
static int parse_largeblob_reply(const cb0r_t key, const cb0r_t value, void *arg) {
    fido_blob_t *chunk = (fido_blob_t*) arg;

    // Somehow this is always one byte too many
    uint64_t chunk_len = value->length - 1;

    // We are just interested in the config (0x01) parameter.
    // See response in https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#largeBlobsRW
    if (key->type != CB0R_INT || key->value != 0x01) {
        return FIDO_OK;
    } else if (value->type != CB0R_BYTE) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    } else if (chunk_len > chunk->max_length) {
        return FIDO_ERR_INTERNAL;
    }
    memcpy(chunk->buffer, value->start + value->header, chunk_len);
    chunk->length = chunk_len;
    return FIDO_OK;
}

/**
 * @brief Receive the answer to the `largeblob_get_tx` request.
 *
 * @param dev The device to read the answer from.
 * @param chunk The chunk to store the returned large blob chunk in. Must already be allocated.
 * @return int FIDO_OK when the operation was successful.
 */
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

typedef struct largeblob_array_lookup_param {
    fido_blob_t *result;
    uint8_t *key;
    bool success;
} largeblob_array_lookup_param_t;

typedef struct largeblob_array_entry {
    uint8_t *ciphertext;
    size_t ciphertext_len;
    uint8_t *nonce; // 12 bytes
    uint8_t associated_data[LARGEBLOB_ASSOCIATED_DATA_SIZE];
    uint8_t *tag; // 16 bytes
    uint64_t origSize;
} largeblob_array_entry_t;

static int fido_uncompress(fido_blob_t* out, uint8_t *compressed, size_t compressed_len, size_t uncompressed_len) {
    if(out->max_length < uncompressed_len) {
        return FIDO_ERR_INVALID_ARGUMENT;
    }
    // TODO INFLATE
    memcpy(out->buffer, compressed, compressed_len);
    out->length = compressed_len;
    return FIDO_OK;
}

static int largeblob_parse_array_entry(cb0r_t key, cb0r_t value, void *data) {
    largeblob_array_entry_t *entry = (largeblob_array_entry_t*) data;

    if (key->type != CB0R_INT) {
        fido_log_debug("%s: cbor type", __func__);
        return FIDO_OK; // ignore
    }

    switch (key->value) {
    case 1: // ciphertext (+tag)
        if(cbor_bytestring_is_definite(value)) {
            return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
        }
        if(value->length < AES_GCM_TAG_SIZE) {
            return FIDO_ERR_INVALID_ARGUMENT;
        }
        entry->ciphertext = value->start + value->header;
        entry->ciphertext_len = value->length - AES_GCM_TAG_SIZE;
        entry->tag = entry->ciphertext + entry->ciphertext_len;
        return FIDO_OK;
    case 2: // nonce
        if(cbor_bytestring_is_definite(value)) {
            return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
        }
        if(value->length != LARGEBLOB_NONCE_SIZE) {
            return FIDO_ERR_INVALID_ARGUMENT;
        }
        entry->nonce = value->start + value->header;
        return FIDO_OK;
    case 3: // origSize
        if (value->type != CB0R_INT || value->value > SIZE_MAX) {
            return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
        }
        entry->origSize = (size_t)value->value;
        entry->associated_data[0] = 'b';
        entry->associated_data[1] = 'l';
        entry->associated_data[2] = 'o';
        entry->associated_data[3] = 'b';
        uint64_t little_endian_orig_size = htole64(entry->origSize);
        memcpy(entry->associated_data + 4, &little_endian_orig_size, sizeof(uint64_t));

        return FIDO_OK;
    default: // ignore
        fido_log_debug("%s: cbor type", __func__);
        return FIDO_OK;
    }
}

static int largeblob_array_lookup(cb0r_t value, void* data) {
    largeblob_array_lookup_param_t *param = (largeblob_array_lookup_param_t*) data;
    largeblob_array_entry_t entry;

    if(param->success) {
        // There already was a successful decryption.
        return FIDO_OK;
    }

    cb0r_s map;
    if (!cb0r_read(value->start + value->header, value->length, &map) || map.type != CB0R_MAP) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    int r;
    if((r = cbor_iter_map(&map, largeblob_parse_array_entry, (void*) &entry)) != FIDO_OK) {
        return r;
    }

    if(aes_gcm_ad(param->key, LARGEBLOB_KEY_SIZE,
        entry.nonce, LARGEBLOB_NONCE_LENGTH,
        entry.ciphertext, entry.ciphertext_len,
        entry.associated_data, sizeof(entry.associated_data),
        entry.tag,
        entry.ciphertext /* Decrypt in-place */) != 0) {
            // Decryption failed. Ignore this entry.
            return FIDO_OK;
        }

    if((r = fido_uncompress(param->result, entry.ciphertext, entry.ciphertext_len, entry.origSize)) != FIDO_OK) {
        // Decompression failed. Ignore this entry.
        return FIDO_OK;
    }
    param->success = true;

    return FIDO_OK;
}

int fido_dev_largeblob_get(fido_dev_t *dev, uint8_t *key, size_t key_len, fido_blob_t *blob) {
    fido_blob_t largeblob_array;
    uint8_t largeblob_array_buffer[dev->maxlargeblob];

    if (key_len != LARGEBLOB_KEY_SIZE) {
        fido_log_debug("%s: invalid key len %zu", __func__, key_len);
        return FIDO_ERR_INVALID_ARGUMENT;
    }

    if (blob == NULL) {
        fido_log_debug("%s: invalid blob_ptr=%p, blob_len=%p", __func__,
            (const void *)blob_ptr, (const void *)blob_len);
        return FIDO_ERR_INVALID_ARGUMENT;
    }

    fido_blob_reset(&largeblob_array, largeblob_array_buffer, sizeof(largeblob_array_buffer));

    int r;
    if ((r = fido_dev_largeblob_get_array(dev, &largeblob_array)) != FIDO_OK) {
        fido_log_debug("%s: largeblob_get_array", __func__);
        return r;
    }

    cb0r_s array;
    if (!cb0r_read(largeblob_array.buffer, largeblob_array.length, &array) || array.type != CB0R_ARRAY) {
        return  FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    largeblob_array_lookup_param_t param = {
        .result = blob,
        .key = key,
        .success = false,
    };

    if ((r = cbor_iter_array(&array, largeblob_array_lookup, &param)) != FIDO_OK) {
        return r;
    }
    if (!param.success) {
        return FIDO_ERR_NOTFOUND;
    }

    return FIDO_OK;
}
