/*
 * Copyright (c) 2020-2022 Yubico AB. All rights reserved.
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include "fido.h"

#include <stdlib.h>
#include <string.h>
#include "iso7816.h"

#define TX_CHUNK_SIZE 240

static const uint8_t aid[]                                  = { 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01 };
static const uint8_t fido_version_u2f[] PROGMEM_MARKER      = "U2F_V2";
static const uint8_t fido_version_fido2[] PROGMEM_MARKER    = "FIDO_2_0";

static int rx_init(fido_dev_t *dev, unsigned char *buf, const size_t len)
{
    fido_ctap_info_t *attr = (fido_ctap_info_t *)buf;
    uint8_t f[64];
    int n;

    if (len != sizeof(*attr)) {
        fido_log_debug("%s: count=%zu", __func__, count);
        return FIDO_ERR_INVALID_PARAM;
    }

    memset(attr, 0, sizeof(*attr));

    if ((n = dev->io.read(dev->io_handle, f, sizeof(f))) < 2 ||
        (f[n - 2] << 8 | f[n - 1]) != SW_NO_ERROR) {
        fido_log_debug("%s: read", __func__);
        return FIDO_ERR_RX;
    }

    n -= 2;

    if (n == (sizeof(fido_version_u2f) - 1) && memcmp_progmem(f, fido_version_u2f, (sizeof(fido_version_u2f) - 1)) == 0) {
        attr->flags = FIDO_CAP_CBOR;
    } else if (n == sizeof(fido_version_fido2) && memcmp_progmem(f, fido_version_fido2, (sizeof(fido_version_fido2) - 1)) == 0) {
        attr->flags = FIDO_CAP_CBOR | FIDO_CAP_NMSG;
    } else {
        fido_log_debug("%s: unknown version string", __func__);
        return FIDO_ERR_RX;
    }

    memcpy(&attr->nonce, &dev->nonce, sizeof(attr->nonce)); /* XXX */

    return (int)len;
}

static int rx_apdu(fido_dev_t *d, uint8_t sw[2], unsigned char **buf, size_t *count) {
    uint8_t f[256 + 2];
    int n, ok = -1;

    if ((n = d->io.read(d->io_handle, f, sizeof(f))) < 2) {
        fido_log_debug("%s: read", __func__);
        goto fail;
    }

    if (fido_buf_write(buf, count, f, (size_t)(n - 2)) < 0) {
        fido_log_debug("%s: fido_buf_write", __func__);
        goto fail;
    }

    memcpy(sw, f + n - 2, 2);

    ok = 0;
fail:
    memset(f, 0, sizeof(f));

    return ok;
}

static int tx_get_response(fido_dev_t *d, uint8_t count)
{
    uint8_t apdu[5];

    memset(apdu, 0, sizeof(apdu));
    apdu[1] = 0xc0; /* GET_RESPONSE */
    apdu[4] = count;

    if (d->io.write(d->io_handle, apdu, sizeof(apdu)) < 0) {
        fido_log_debug("%s: write", __func__);
        return FIDO_ERR_TX;
    }

    return FIDO_OK;
}

static int rx_msg(fido_dev_t *dev, unsigned char *buf, const size_t bufsiz) {
    uint8_t sw[2];
    size_t count = bufsiz;

    if (rx_apdu(dev, sw, &buf, &count) < 0) {
        fido_log_debug("%s: preamble", __func__);
        return FIDO_ERR_RX;
    }

    while (sw[0] == SW1_MORE_DATA) {
        if (tx_get_response(dev, sw[1]) < 0 ||
            rx_apdu(dev, sw, &buf, &count) < 0) {
            fido_log_debug("%s: chain", __func__);
            return FIDO_ERR_RX;
        }
    }

    if (fido_buf_write(&buf, &count, sw, sizeof(sw)) < 0) {
        fido_log_debug("%s: sw", __func__);
        return FIDO_ERR_RX;
    }

    // TODO bufsiz - count > INT_MAX
    if (bufsiz < count) {
        fido_log_debug("%s: bufsiz", __func__);
        return FIDO_ERR_RX;
    }

    return (int)(bufsiz - count);
}

static int rx_cbor(fido_dev_t *dev, unsigned char *buf, const size_t count) {
    int r;

    if ((r = rx_msg(dev, buf, count)) < 2)
        return FIDO_ERR_RX;

    return r - 2;
}

static int nfc_rx(struct fido_dev *dev, const uint8_t cmd, unsigned char *buf, const size_t len) {
    switch (cmd) {
    case CTAP_CMD_INIT:
        return rx_init(dev, buf, len);
    case CTAP_CMD_CBOR:
        return rx_cbor(dev, buf, len);
    case CTAP_CMD_MSG:
        return rx_msg(dev, buf, len);
    default:
        fido_log_debug("%s: cmd=%02x", __func__, cmd);
        return FIDO_ERR_INVALID_PARAM;
    }
}

static int tx_short_apdu(
    fido_dev_t *dev,
    const iso7816_header_t *h,
    const uint8_t *payload,
    uint8_t payload_len,
    uint8_t cla_flags
) {
    // TODO: Prevent copying if possible.
    uint8_t apdu[5 + UINT8_MAX];
    uint8_t status_word[2];
    size_t apdu_len;
    int ok = FIDO_ERR_TX;

    memset(&apdu, 0, sizeof(apdu));
    // Copy the header.
    apdu[0] = h->cla | cla_flags;
    apdu[1] = h->ins;
    apdu[2] = h->p1;
    apdu[3] = h->p2;
    apdu[4] = payload_len;
    memcpy(&apdu[5], payload, payload_len);
    apdu_len = (size_t)(5 + payload_len);

    if (dev->io.write(dev->io_handle, apdu, apdu_len) < 0) {
        fido_log_debug("%s: write", __func__);
        goto fail;
    }

    if (cla_flags & CLA_CHAIN_CONTINUE) {
        if (dev->io.read(dev->io_handle, status_word, sizeof(status_word)) != 2) {
            fido_log_debug("%s: read", __func__);
            goto fail;
        }
        if ((status_word[0] << 8 | status_word[1]) != SW_NO_ERROR) {
            fido_log_debug("%s: unexpected status word", __func__);
            goto fail;
        }
    }

    ok = FIDO_OK;
fail:
    memset(apdu, 0, sizeof(apdu));

    return ok;
}

static int nfc_do_tx(fido_dev_t *dev, const iso7816_apdu_t *apdu) {
    uint16_t apdu_len = apdu->payload_len;

    const uint8_t *apdu_ptr = apdu->payload_ptr;

    while (apdu_len > TX_CHUNK_SIZE) {
        if (tx_short_apdu(dev, &apdu->header, apdu_ptr, TX_CHUNK_SIZE, CLA_CHAIN_CONTINUE) < 0) {
            fido_log_debug("%s: chain", __func__);
            return FIDO_ERR_TX;
        }
        apdu_ptr += TX_CHUNK_SIZE;
        apdu_len -= TX_CHUNK_SIZE;
    }

    if (tx_short_apdu(dev, &apdu->header, apdu_ptr, (uint8_t)apdu_len, 0) < 0) {
        fido_log_debug("%s: tx_short_apdu", __func__);
        return FIDO_ERR_TX;
    }

    return FIDO_OK;
}

static int nfc_tx(struct fido_dev *dev, const uint8_t cmd, const unsigned char *buf, const size_t len) {
    iso7816_apdu_t apdu;
    int status = FIDO_ERR_TX;

    switch (cmd) {
    case CTAP_CMD_INIT: /* select */
        iso7816_init(&apdu, 0, 0xa4, 0x04, aid, sizeof(aid));
        break;
    case CTAP_CMD_CBOR: /* wrap cbor */
        iso7816_init(&apdu, 0x80, 0x10, 0x00, buf, (uint16_t)len);
        break;
    case CTAP_CMD_MSG: /* already an apdu */
        iso7816_init_from_bytes(&apdu, buf, len);
        break;
    default:
        fido_log_debug("%s: cmd=%02x", __func__, cmd);
        goto fail;
    }

    if (nfc_do_tx(dev, &apdu) < 0) {
        fido_log_debug("%s: nfc_do_tx", __func__);
        goto fail;
    }

    status = FIDO_OK;
fail:

    return status;
}

static const fido_dev_transport_t nfc_transport = {
    .rx = nfc_rx,
    .tx = nfc_tx,
};

int fido_init_nfc_device(fido_dev_t *dev, const fido_dev_io_t *io) {
    if (dev->io_handle != NULL) {
        fido_log_debug("%s: invalid argument, device already open", __func__);
        return FIDO_ERR_INVALID_ARGUMENT;
    }
    fido_dev_set_io(dev, io);
    fido_dev_set_transport(dev, &nfc_transport);

    return FIDO_OK;
}
