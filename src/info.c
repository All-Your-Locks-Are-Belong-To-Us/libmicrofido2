#include "fido.h"

void fido_cbor_info_reset(fido_cbor_info_t *ci)
{
    // TODO: Reset ci
//    fido_str_array_free(&ci->versions);
//    fido_str_array_free(&ci->extensions);
//    fido_str_array_free(&ci->transports);
//    fido_opt_array_free(&ci->options);
//    fido_byte_array_free(&ci->protocols);
//    fido_algo_array_free(&ci->algorithms);
}

static int parse_reply_element(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
    fido_cbor_info_t *ci = arg;

    if (cbor_isa_uint(key) == false ||
        cbor_int_get_width(key) != CBOR_INT_8) {
        fido_log_debug("%s: cbor type", __func__);
        return (0); /* ignore */
    }

    switch (cbor_get_uint8(key)) {
        case 1: /* versions */
            return (decode_string_array(val, &ci->versions));
        case 2: /* extensions */
            return (decode_string_array(val, &ci->extensions));
        case 3: /* aaguid */
            return (decode_aaguid(val, ci->aaguid, sizeof(ci->aaguid)));
        case 4: /* options */
            return (decode_options(val, &ci->options));
        case 5: /* maxMsgSize */
            return (cbor_decode_uint64(val, &ci->maxmsgsize));
        case 6: /* pinProtocols */
            return (decode_protocols(val, &ci->protocols));
        case 7: /* maxCredentialCountInList */
            return (cbor_decode_uint64(val, &ci->maxcredcntlst));
        case 8: /* maxCredentialIdLength */
            return (cbor_decode_uint64(val, &ci->maxcredidlen));
        case 9: /* transports */
            return (decode_string_array(val, &ci->transports));
        case 10: /* algorithms */
            return (decode_algorithms(val, &ci->algorithms));
        case 11: /* maxSerializedLargeBlobArray */
            return (cbor_decode_uint64(val, &ci->maxlargeblob));
        case 14: /* fwVersion */
            return (cbor_decode_uint64(val, &ci->fwversion));
        case 15: /* maxCredBlobLen */
            return (cbor_decode_uint64(val, &ci->maxcredbloblen));
        default: /* ignore */
            fido_log_debug("%s: cbor type", __func__);
            return (0);
    }
}

static int fido_dev_get_cbor_info_tx(fido_dev_t *dev)
{
    const unsigned char cbor[] = { CTAP_CBOR_GETINFO };

    fido_log_debug("%s: dev=%p", __func__, (void *)dev);

    if (fido_tx(dev, CTAP_CMD_CBOR, cbor, sizeof(cbor)) < 0) {
        fido_log_debug("%s: fido_tx", __func__);
        return FIDO_ERR_TX;
    }

    return FIDO_OK;
}

static int fido_dev_get_cbor_info_rx(fido_dev_t *dev, fido_cbor_info_t *ci)
{
    unsigned char msg[FIDO_MAXMSG];
    int		 msglen;
    int		 r;

    fido_log_debug("%s: dev=%p, ci=%p, ms=%d", __func__, (void *)dev,
                   (void *)ci, *ms);

    fido_cbor_info_reset(ci);

    if ((msglen = fido_rx(dev, CTAP_CMD_CBOR, msg, FIDO_MAXMSG)) < 0) {
        fido_log_debug("%s: fido_rx", __func__);
        r = FIDO_ERR_RX;
        goto out;
    }

    // TODO: Implement CBOR here
    r = cbor_parse_reply(msg, (size_t)msglen, ci, parse_reply_element);
    out:

    return (r);
}

int fido_dev_get_cbor_info_wait(fido_dev_t *dev, fido_cbor_info_t *ci)
{
    int r;

    if ((r = fido_dev_get_cbor_info_tx(dev)) != FIDO_OK ||
        (r = fido_dev_get_cbor_info_rx(dev, ci)) != FIDO_OK)
        return (r);

    return (FIDO_OK);
}


uint64_t fido_cbor_info_maxmsgsize(const fido_cbor_info_t *ci)
{
    return (ci->maxmsgsize);
}
