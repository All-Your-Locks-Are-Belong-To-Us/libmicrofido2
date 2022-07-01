/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#pragma once

#include "cb0r.h"
#include <stdbool.h>

#define CBOR_WRITER_OK 0
#define CBOR_WRITER_BUFFER_TOO_SHORT 1

typedef int cbor_parse_array_item(const cb0r_t value, void *data);
typedef int cbor_parse_map_item(const cb0r_t key, const cb0r_t value, void *data);

/**
 * @brief Iterate over a CBOR map calling the callback for every entry.
 * 
 * @param cbor_map The map to iterate over.
 * @param cb The callback to call for each entry.
 * @param data User-supplied additional context data passed to the callback.
 * @return int FIDO_OK if map could be iterated completely.
 */
int cbor_iter_map(cb0r_t cbor_map, cbor_parse_map_item *cb, void *data);

/**
 * @brief Iterate over a CBOR array calling the callback for every entry.
 * 
 * @param cbor_array The array to iterate over.
 * @param cb The callback to call for each entry.
 * @param data User-supplied additional context data passed to the callback.
 * @return int FIDO_OK if array could be iterated completely.
 */
int cbor_iter_array(cb0r_t cbor_array, cbor_parse_array_item *cb, void* data);

/**
 * @brief Tests whether the given UTF-8 string is definite.
 * 
 * @param val The value to test.
 * @return true when the UTF-8 string is definite, false otherwise.
 */
bool cbor_utf8string_is_definite(const cb0r_t val);

/**
 * @brief Tests whether the given byte string is definite.
 *
 * @param val The value to test.
 * @return true when the bytestring is definite, false otherwise.
 */
bool cbor_bytestring_is_definite(const cb0r_t val);

typedef struct cbor_writer {
    // buffer points to the written data.
    uint8_t *buffer;

    // writing_position points to where data will next be written.
    uint8_t *writing_position;

    // buffer_len is the length of buffer.
    size_t buffer_len;

    // length is the length of data written to buffer.
    size_t length;

    // status indicates whether something went wrong while writing.
    int status;
} cbor_writer_s, *cbor_writer_t;

/**
 * @brief Reset the cbor writer
 *
 * @param writer The writer to reset.
 * @param buffer The new buffer.
 * @param writer The length of buffer.
 */
void cbor_writer_reset(cbor_writer_t writer, uint8_t* buffer, size_t buffer_len);

/**
 * @brief Check a writer's status.
 *
 * @param writer The writer to check.
 * @return true iff no error occurred and writer->buffer can be used.
 */
bool cbor_writer_is_ok(cbor_writer_t writer);

/**
 * @brief Writes an unsigned int.
 *
 * @param writer The writer to use.
 * @param value The integer value to write.
 * @return number of bytes written.
 */
size_t cbor_encode_uint(cbor_writer_t writer, uint64_t value);

/**
 * @brief Writes a negative int.
 *
 * @param writer The writer to use.
 * @param value The value to write. The interpretation the negative int is (-value - 1).
 * @return number of bytes written.
 */
size_t cbor_encode_negint(cbor_writer_t writer, uint64_t value);

/**
 * @brief Writes a bytestring.
 *
 * @param writer The writer to use.
 * @param string The string to write.
 * @param string_len The length of the string.
 * @return number of bytes written.
 */
size_t cbor_encode_bytestring(cbor_writer_t writer, uint8_t* string, size_t string_len);

/**
 * @brief Writes a UTF-8 string.
 *
 * @param writer The writer to use.
 * @param string The string to write.
 * @param string_len The length of the string.
 * @return number of bytes written.
 */
size_t cbor_encode_string(cbor_writer_t writer, uint8_t* string, size_t string_len);

/**
 * @brief Writes the header of an array.
 *
 * @param writer The writer to use.
 * @param len The number of elements in the array.
 * @return number of bytes written.
 */
size_t cbor_encode_array_start(cbor_writer_t writer, uint64_t len);

/**
 * @brief Writes the header of a map.
 *
 * @param writer The writer to use.
 * @param len The number of entries (tuples) in the map.
 * @return number of bytes written.
 */
size_t cbor_encode_map_start(cbor_writer_t writer, uint64_t len);

/**
 * @brief Writes a boolean.
 *
 * @param writer The writer to use.
 * @param value The value to write.
 * @return number of bytes written.
 */
size_t cbor_encode_boolean(cbor_writer_t writer, bool value);
