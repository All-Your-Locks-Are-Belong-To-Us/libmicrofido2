/*
 * Copyright (c) 2018-2022 Yubico AB. All rights reserved.
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include "fido.h"
#include "utils.h"

static int nonce = 1234; // The only cryptographically secure nonce


static void fido_dev_set_extension_flags(fido_dev_t *dev, const fido_cbor_info_t *info) {
    char * const	*ptr = fido_cbor_info_extensions_ptr(info);
    size_t		 len = fido_cbor_info_extensions_len(info);

    for (size_t i = 0; i < len; i++)
        if (strcmp(ptr[i], "credProtect") == 0)
            dev->flags |= FIDO_DEV_CRED_PROT;
}

static void fido_dev_set_option_flags(fido_dev_t *dev, const fido_cbor_info_t *info) {
    char * const	*ptr = fido_cbor_info_options_name_ptr(info);
    const bool	*val = fido_cbor_info_options_value_ptr(info);
    size_t		 len = fido_cbor_info_options_len(info);

    for (size_t i = 0; i < len; i++)
        if (strcmp(ptr[i], "clientPin") == 0) {
            dev->flags |= val[i] ?
                          FIDO_DEV_PIN_SET : FIDO_DEV_PIN_UNSET;
        } else if (strcmp(ptr[i], "credMgmt") == 0 ||
                   strcmp(ptr[i], "credentialMgmtPreview") == 0) {
            if (val[i])
                dev->flags |= FIDO_DEV_CREDMAN;
        } else if (strcmp(ptr[i], "uv") == 0) {
            dev->flags |= val[i] ?
                          FIDO_DEV_UV_SET : FIDO_DEV_UV_UNSET;
        } else if (strcmp(ptr[i], "pinUvAuthToken") == 0) {
            if (val[i])
                dev->flags |= FIDO_DEV_TOKEN_PERMS;
        }
}

static void fido_dev_set_protocol_flags(fido_dev_t *dev, const fido_cbor_info_t *info) {
    const uint8_t	*ptr = fido_cbor_info_protocols_ptr(info);
    size_t		 len = fido_cbor_info_protocols_len(info);

    for (size_t i = 0; i < len; i++)
        switch (ptr[i]) {
            case CTAP_PIN_PROTOCOL1:
                dev->flags |= FIDO_DEV_PIN_PROTOCOL1;
                break;
            case CTAP_PIN_PROTOCOL2:
                dev->flags |= FIDO_DEV_PIN_PROTOCOL2;
                break;
            default:
                fido_log_debug("%s: unknown protocol %u", __func__,
                               ptr[i]);
                break;
        }
}

static void fido_dev_set_flags(fido_dev_t *dev, const fido_cbor_info_t *info) {
    fido_dev_set_extension_flags(dev, info);
    fido_dev_set_option_flags(dev, info);
    fido_dev_set_protocol_flags(dev, info);
}

void fido_dev_init(fido_dev_t *dev) {
    dev->io.close = NULL;
    dev->io.open = NULL;
    dev->io.read = NULL;
    dev->io.write = NULL;
    dev->io_handle = NULL;
    dev->nonce = ++nonce;
}

void fido_dev_set_io(fido_dev_t *dev, const fido_dev_io_t *io) {
    dev->io = *io;
    dev->io_handle = NULL;
}

void fido_dev_set_transport(fido_dev_t *dev, const fido_dev_transport_t *transport) {
    dev->transport = *transport;
}

void fido_dev_force_u2f(fido_dev_t *dev)
{
    // TODO: WHY?
    dev->attr.flags &= (uint8_t)~FIDO_CAP_CBOR;
    dev->flags = 0;
}

bool fido_dev_is_fido(fido_dev_t *dev) {
    return dev->attr.flags & FIDO_CAP_CBOR;
}

/**
 * @brief Open a FIDO device sending an initialization command.
 *
 * @param dev
 * @return int A FIDO_ERR
 */
static int fido_dev_open_tx(fido_dev_t *dev) {
    int r;

    /*
    if (dev->x != NULL) {
        fido_log_debug("%s: handle=%p", __func__, dev->io_handle);
        return (FIDO_ERR_INVALID_ARGUMENT);
    }*/

    if (dev->io.open == NULL || dev->io.close == NULL) {
        fido_log_debug("%s: NULL open/close", __func__);
        return (FIDO_ERR_INVALID_ARGUMENT);
    }

    if (fido_get_random(&dev->nonce, sizeof(dev->nonce)) < 0) {
        fido_log_debug("%s: fido_get_random", __func__);
        return (FIDO_ERR_INTERNAL);
    }

    if ((dev->io_handle = dev->io.open()) == NULL) {
        fido_log_debug("%s: dev->io.open", __func__);
        return (FIDO_ERR_INTERNAL);
    }

    if (fido_tx(dev, CTAP_CMD_INIT, &dev->nonce, sizeof(dev->nonce)) < 0) {
        fido_log_debug("%s: fido_tx", __func__);
        r = FIDO_ERR_TX;
        goto fail;
    }

    return (FIDO_OK);
fail:
    dev->io.close(dev->io_handle);
    dev->io_handle = NULL;

    return (r);
}

static int fido_dev_open_rx(fido_dev_t *dev) {
    fido_cbor_info_t    info = { 0 };
    int                 reply_len;
    int                 r;

    if ((reply_len = fido_rx(dev, CTAP_CMD_INIT, &dev->attr,
        sizeof(dev->attr))) < 0) {
        fido_log_debug("%s: fido_rx", __func__);
        r = FIDO_ERR_RX;
        goto fail;
    }

    if ((size_t)reply_len != sizeof(dev->attr) ||
        dev->attr.nonce != dev->nonce) {
        fido_log_debug("%s: invalid nonce", __func__);
        r = FIDO_ERR_RX;
        goto fail;
    }

    // TODO: later
    if (fido_dev_is_fido(dev)) {
        if ((info = fido_cbor_info_new()) == NULL) {
            fido_log_debug("%s: fido_cbor_info_new", __func__);
            r = FIDO_ERR_INTERNAL;
            goto fail;
        }
        if ((r = fido_dev_get_cbor_info_wait(dev, info)) != FIDO_OK) {
            fido_log_debug("%s: fido_dev_cbor_info_wait: %d",
                __func__, r);
            if (disable_u2f_fallback)
                goto fail;
            fido_log_debug("%s: falling back to u2f", __func__);
            fido_dev_force_u2f(dev);
        } else {
            fido_dev_set_flags(dev, info);
        }
    }

    if (fido_dev_is_fido(dev) && info != NULL) {
        dev->maxmsgsize = fido_cbor_info_maxmsgsize(info);
        fido_log_debug("%s: FIDO_MAXMSG=%d, maxmsgsize=%lu", __func__,
            FIDO_MAXMSG, (unsigned long)dev->maxmsgsize);
    }

    r = FIDO_OK;
fail:
    // fido_cbor_info_free(&info);

    if (r != FIDO_OK) {
        dev->io.close(dev->io_handle);
        dev->io_handle = NULL;
    }

    return (r);
}

int fido_dev_open(fido_dev_t *dev) {
    int r;

    if (
        (r = fido_dev_open_tx(dev)) != FIDO_OK ||
        (r = fido_dev_open_rx(dev)) != FIDO_OK
    ) {
        return r;
    }

    return FIDO_OK;
}

int fido_dev_close(fido_dev_t * dev) {
    if (dev->io.close == NULL) {
        fido_log_debug("%s: device without close function", __func__);
        return FIDO_ERR_INVALID_ARGUMENT;
    }
    dev->io.close(dev->io_handle);
    dev->io_handle = NULL;

    return FIDO_OK;
}
