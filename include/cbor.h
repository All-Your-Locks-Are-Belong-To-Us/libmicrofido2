#pragma once

#include "cb0r.h"
#include <stdbool.h>

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
 * @return true or false.
 */
bool cbor_utf8string_is_definite(const cb0r_t val);

/**
 * @brief Tests whether the given byte string is definite.
 *
 * @param val The value to test.
 * @return true or false.
 */
bool cbor_bytestring_is_definite(const cb0r_t val);