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
#include <string.h>

static int nonce = 1234; // The only cryptographically secure nonce


static void fido_dev_set_extension_flags(fido_dev_t *dev, const fido_cbor_info_t *info) {
    if (info->extensions & FIDO_EXTENSION_CRED_PROTECT) {
        dev->flags |= FIDO_DEV_CRED_PROT;
    }
    if (info->extensions & FIDO_EXTENSION_LARGE_BLOB_KEY) {
        dev->flags |= FIDO_DEV_LARGE_BLOB_KEY;
    }
}

static void fido_dev_set_option_flags(fido_dev_t *dev, const fido_cbor_info_t *info) {
    if(info->options & FIDO_OPTION_CLIENT_PIN) {
        dev->flags |= FIDO_DEV_PIN_SET;
    }
    if(info->options & FIDO_OPTION_CRED_MGMT || info->options & FIDO_OPTION_CREDENTIAL_MANAGEMENT_PREVIEW) {
        dev->flags |= FIDO_DEV_CREDMAN;
    }
    if(info->options & FIDO_OPTION_UV) {
        dev->flags |= FIDO_DEV_UV_SET;
    }
    if(info->options & FIDO_OPTION_PIN_UV_AUTH_TOKEN) {
        dev->flags |= FIDO_DEV_TOKEN_PERMS;
    }
    if(info->options & FIDO_OPTION_LARGE_BLOBS) {
        dev->flags |= FIDO_DEV_LARGE_BLOB;
    }
}

static void fido_dev_set_protocol_flags(fido_dev_t *dev, const fido_cbor_info_t *info) {
    if(info->protocols & FIDO_PIN_PROTOCOL_1){
        dev->flags |= FIDO_DEV_PIN_PROTOCOL_1;
    }
    if(info->protocols & FIDO_PIN_PROTOCOL_2){
        dev->flags |= FIDO_DEV_PIN_PROTOCOL_2;
    }
}

static void fido_dev_set_flags(fido_dev_t *dev, const fido_cbor_info_t *info) {
    fido_dev_set_extension_flags(dev, info);
    fido_dev_set_option_flags(dev, info);
    fido_dev_set_protocol_flags(dev, info);
}

void fido_dev_init(fido_dev_t *dev) {
    dev->io_handle = NULL;
    dev->rx_len = 0;
    dev->tx_len = 0;
    dev->nonce = ++nonce;
    dev->flags = 0;
    dev->maxmsgsize = FIDO_MAXMSG;
    dev->maxlargeblob = 0;

    memset(&(dev->io),        0, sizeof(fido_dev_io_t));
    memset(&(dev->attr),      0, sizeof(fido_ctap_info_t));
    memset(&(dev->transport), 0, sizeof(fido_dev_transport_t));
}

void fido_dev_set_io(fido_dev_t *dev, const fido_dev_io_t *io) {
    dev->io = *io;
    dev->io_handle = NULL;
}

void fido_dev_set_transport(fido_dev_t *dev, const fido_dev_transport_t *transport) {
    dev->transport = *transport;
}

bool fido_dev_is_fido(fido_dev_t *dev) {
    // TODO: Check whether this is standard conform.
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
        return FIDO_ERR_INVALID_ARGUMENT;
    }

    if(fido_get_random == NULL) {
        fido_log_debug("%s: fido_get_random is NULL", __func__);
        return FIDO_ERR_INTERNAL;
    }

    if (fido_get_random((uint8_t*) &dev->nonce, sizeof(dev->nonce)) < 0) {
        fido_log_debug("%s: fido_get_random", __func__);
        return FIDO_ERR_INTERNAL;
    }

    if ((dev->io_handle = dev->io.open()) == NULL) {
        fido_log_debug("%s: dev->io.open", __func__);
        return FIDO_ERR_INTERNAL;
    }

    if (fido_tx(dev, CTAP_CMD_INIT, &dev->nonce, sizeof(dev->nonce)) < 0) {
        fido_log_debug("%s: fido_tx", __func__);
        r = FIDO_ERR_TX;
        goto fail;
    }

    return FIDO_OK;
fail:
    dev->io.close(dev->io_handle);
    dev->io_handle = NULL;

    return r;
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

    if (fido_dev_is_fido(dev)) {
        fido_cbor_info_reset(&info);
        if ((r = fido_dev_get_cbor_info_wait(dev, &info)) != FIDO_OK) {
            fido_log_debug("%s: fido_dev_cbor_info_wait: %d", __func__, r);
            // This device does not support FIDO2, error out.
            goto fail;
        } else {
            fido_dev_set_flags(dev, &info);
            dev->maxmsgsize = info.maxmsgsize < FIDO_MAXMSG ? info.maxmsgsize : FIDO_MAXMSG;
            fido_log_debug("%s: FIDO_MAXMSG=%d, maxmsgsize=%lu", __func__,
                FIDO_MAXMSG, (unsigned long)dev->maxmsgsize);
            dev->maxlargeblob = info.maxlargeblob;
        }
    }

    r = FIDO_OK;
fail:
    if (r != FIDO_OK) {
        dev->io.close(dev->io_handle);
        dev->io_handle = NULL;
    }

    return r;
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
