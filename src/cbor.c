#include "cbor.h"

static int check_key_type(cbor_item_t *item)
{
    if (item->type == CBOR_TYPE_UINT || item->type == CBOR_TYPE_NEGINT ||
        item->type == CBOR_TYPE_STRING)
        return 0;

    fido_log_debug("%s: invalid type: %d", __func__, item->type);

    return -1;
}


/*
 * Validate CTAP2 canonical CBOR encoding rules for maps.
 */
static int ctap_check_cbor(cbor_item_t *prev, cbor_item_t *curr)
{
    size_t	curr_len;
    size_t	prev_len;

    if (check_key_type(prev) < 0 || check_key_type(curr) < 0)
        return (-1);

    if (prev->type != curr->type) {
        if (prev->type < curr->type)
            return (0);
        fido_log_debug("%s: unsorted types", __func__);
        return (-1);
    }

    if (curr->type == CBOR_TYPE_UINT || curr->type == CBOR_TYPE_NEGINT)
        // TODO: cbor_int_get_width is external
        if (cbor_int_get_width(curr) >= cbor_int_get_width(prev) &&
            // TODO: cbor_get_int is external
            cbor_get_int(curr) > cbor_get_int(prev))
            return (0);
    } else {
        // TODO: cbor_string_length is external
        curr_len = cbor_string_length(curr);
        prev_len = cbor_string_length(prev);

        if (curr_len > prev_len || (curr_len == prev_len &&
                                    // TODO: cbor_string_handle is external
                                    memcmp(cbor_string_handle(prev), cbor_string_handle(curr),
                                           curr_len) < 0))
            return (0);
    }

    fido_log_debug("%s: invalid cbor", __func__);

    return (-1);
}



int cbor_map_iter(const cbor_item_t *item, void *arg, int(*f)(const cbor_item_t *,
                                                          const cbor_item_t *, void *))
{
    struct cbor_pair	*v;
    size_t			 n;

    // TODO: cbor_map_handle is external
    if ((v = cbor_map_handle(item)) == NULL) {
        fido_log_debug("%s: cbor_map_handle", __func__);
        return (-1);
    }

    // TODO: cbor_map_size is external
    n = cbor_map_size(item);

    for (size_t i = 0; i < n; i++) {
        if (v[i].key == NULL || v[i].value == NULL) {
            fido_log_debug("%s: key=%p, value=%p for i=%zu",
                           __func__, (void *)v[i].key, (void *)v[i].value, i);
            return (-1);
        }
        if (i && ctap_check_cbor(v[i - 1].key, v[i].key) < 0) {
            fido_log_debug("%s: ctap_check_cbor", __func__);
            return (-1);
        }
        if (f(v[i].key, v[i].value, arg) < 0) {
            fido_log_debug("%s: iterator < 0 on i=%zu", __func__,
                           i);
            return (-1);
        }
    }

    return (0);
}


int cbor_parse_reply(const unsigned char *blob, size_t blob_len, void *arg,
                 int(*parser)(const cbor_item_t *, const cbor_item_t *, void *))
{
    cbor_item_t		*item = NULL;
    struct cbor_load_result	 cbor;
    int			 r;

    if (blob_len < 1) {
        fido_log_debug("%s: blob_len=%zu", __func__, blob_len);
        r = FIDO_ERR_RX;
        goto fail;
    }

    if (blob[0] != FIDO_OK) {
        fido_log_debug("%s: blob[0]=0x%02x", __func__, blob[0]);
        r = blob[0];
        goto fail;
    }

    // TODO: cbor_load is from libcbor
    if ((item = cbor_load(blob + 1, blob_len - 1, &cbor)) == NULL) {
        fido_log_debug("%s: cbor_load", __func__);
        r = FIDO_ERR_RX_NOT_CBOR;
        goto fail;
    }

    // TODO: cbor_isa_map is from libcbor
    if (cbor_isa_map(item) == false ||
        cbor_map_is_definite(item) == false) {
        fido_log_debug("%s: cbor type", __func__);
        r = FIDO_ERR_RX_INVALID_CBOR;
        goto fail;
    }

    if (cbor_map_iter(item, arg, parser) < 0) {
        fido_log_debug("%s: cbor_map_iter", __func__);
        r = FIDO_ERR_RX_INVALID_CBOR;
        goto fail;
    }

    r = FIDO_OK;
    fail:
    if (item != NULL)
        cbor_decref(&item);

    return (r);
}
