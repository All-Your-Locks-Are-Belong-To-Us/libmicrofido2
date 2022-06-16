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
