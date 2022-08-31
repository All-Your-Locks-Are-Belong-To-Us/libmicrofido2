/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include "cbor.h"
#include "fido.h"

int cbor_iter_map(cb0r_t cbor_map, cbor_parse_map_item *cb, void *data) {
    int r;
    if (cbor_map->count % 2 > 0 || cbor_map->type != CB0R_MAP) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }
    
    cb0r_s map_key;
    cb0r_s map_value;
    size_t entry_count = cbor_map->count / 2;
    for(size_t i = 0; i < entry_count; i++) {
        if (!cb0r_get(cbor_map, 2 * i, &map_key) || !cb0r_get(cbor_map, 2 * i + 1, &map_value)) {
            return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
        }
        r = cb(&map_key, &map_value, data);
        if(r != FIDO_OK) {
            return r;
        }
    }
    return FIDO_OK;
}


int cbor_iter_array(cb0r_t cbor_array, cbor_parse_array_item *cb, void *data) {
    int r;
    if(cbor_array->type != CB0R_ARRAY) {
        return FIDO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    size_t entry_count = cbor_array->count;
    cb0r_s element;

    for(size_t i = 0; i < entry_count; i++) {
        if(!cb0r_get(cbor_array, i , &element)) {
            return FIDO_ERR_INVALID_CBOR;
        }
        r = cb(&element, data);
        if(r != FIDO_OK) {
            return r;
        }
    }
    return FIDO_OK;
}

bool cbor_utf8string_is_definite(const cb0r_t val) {
    return val->type == CB0R_UTF8 &&
        val->count != CB0R_STREAM;
}

bool cbor_bytestring_is_definite(const cb0r_t val) {
    return val->type == CB0R_BYTE &&
        val->count != CB0R_STREAM;
}

/**
 * @brief Returns the length in bytes when encoding the value for CBOR.
 * Essentially, all values greater than 23 are encoded with 1 byte more than
 * what would usually be necessary, to accomodate additional metadata.
 * See https://datatracker.ietf.org/doc/html/rfc7049#section-2.1
 *
 * @param value The value to encode.
 */
static size_t cbor_encoded_len(uint64_t value) {
    if(value <= 23) {
        return 1;
    } else if(value <= UINT8_MAX) {
        return 2;
    } else if(value <= UINT16_MAX) {
        return 3;
    } else if(value <= UINT32_MAX) {
        return 5;
    } else {
        return 9;
    }
}

void cbor_writer_reset(cbor_writer_t writer, uint8_t* buffer, const size_t buffer_len) {
    writer->buffer = buffer;
    writer->buffer_len = buffer_len;
    writer->writing_position = buffer;
    writer->length = 0;
    writer->status = CBOR_WRITER_OK;
}

bool cbor_writer_is_ok(cbor_writer_t writer) {
    return writer->status == CBOR_WRITER_OK;
}

/**
 * @brief Return whether the CBOR writer can advance.
 *
 * @param writer The CBOR writer object.
 * @param count The amount of bytes to advance the writer
 * @return bool whether the writer can advance
 */
static bool cbor_writer_can_advance(cbor_writer_t writer, const size_t count) {
    if(count > writer->buffer_len - writer->length || writer->status != CBOR_WRITER_OK) {
        return false;
    }
    return true;
}

/**
 * @brief Ensure that the writer can advance and advance if possible. Otherwise set the writer status.
 *
 * @param writer The CBOR writer object.
 * @param count The amount of bytes to advance the writer
 * @return bool whether the writer can advance
 */
static void cbor_writer_advance(cbor_writer_t writer, const size_t count) {
    if(cbor_writer_can_advance(writer, count)) {
        writer->length += count;
        writer->writing_position = writer->buffer + writer->length;
    } else {
        writer->status = CBOR_WRITER_BUFFER_TOO_SHORT;
    }
}

/**
 * @brief Write a CBOR value using the writer.
 *
 * @param writer The CBOR writer object.
 * @param type The CBOR type of the data to write.
 * @param value The value to write.
 * @return size_t the amount of bytes written.
 */
static size_t cbor_write(cbor_writer_t writer, cb0r_e type, const uint64_t value) {
    size_t encoded_len = cbor_encoded_len(value);
    if(!cbor_writer_can_advance(writer, encoded_len)) {
        writer->status = CBOR_WRITER_BUFFER_TOO_SHORT;
        return 0;
    }
    encoded_len = cb0r_write(writer->writing_position, type, value);
    cbor_writer_advance(writer, encoded_len);
    return encoded_len;
}

size_t cbor_encode_uint(cbor_writer_t writer, const uint64_t value) {
    return cbor_write(writer, CB0R_INT, value);
}

size_t cbor_encode_negint(cbor_writer_t writer, const uint64_t value) {
    return cbor_write(writer, CB0R_NEG, value);
};

size_t cbor_encode_bytestring(cbor_writer_t writer, const uint8_t* string, const size_t string_len) {
    size_t header_len = cbor_write(writer, CB0R_BYTE, string_len);
    if(cbor_writer_can_advance(writer, string_len)) {
        memcpy(writer->writing_position, string, string_len);
        cbor_writer_advance(writer, string_len);
        return header_len + string_len;
    }
    return header_len;
}

size_t cbor_encode_string(cbor_writer_t writer, const uint8_t* string, const size_t string_len) {
    size_t header_len = cbor_write(writer, CB0R_UTF8, string_len);
    if(cbor_writer_can_advance(writer, string_len)) {
        memcpy(writer->writing_position, string, string_len);
        cbor_writer_advance(writer, string_len);
        return header_len + string_len;
    }
    return header_len;
}

size_t cbor_encode_array_start(cbor_writer_t writer, const uint64_t len) {
    return cbor_write(writer, CB0R_ARRAY, len);
}

size_t cbor_encode_map_start(cbor_writer_t writer, const uint64_t len) {
    return cbor_write(writer, CB0R_MAP, len);
}

size_t cbor_encode_boolean(cbor_writer_t writer, const bool value) {
    return cbor_write(writer, value ? CB0R_TRUE : CB0R_FALSE, 0);
}
