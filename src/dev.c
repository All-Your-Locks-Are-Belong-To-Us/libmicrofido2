#include "fido.h"
#include "utils.h"

static int nonce = 1234; // The only cryptographically secure nonce

/**
 * @brief Initialize a FIDO device.
 *
 * Brings the device structure into a known state, resetting everything.
 *
 * @param dev A pointer to the uninitialized FIDO device.
 */
void fido_dev_init(fido_dev_t *dev) {
    dev->io.close = NULL;
    dev->io.open = NULL;
    dev->io.read = NULL;
    dev->io.write = NULL;
    dev->io_handle = NULL;
    dev->nonce = ++nonce;
}

/**
 * @brief Set the I/O functions for a device.
 *
 * @param dev A pointer to the FIDO device to set the I/O functions for.
 * @param io The I/O functions to set.
 */
void fido_dev_set_io(fido_dev_t *dev, const fido_dev_io_t *io) {
    dev->io = *io;
    dev->io_handle = NULL;
}

/**
 * @brief Set the transport functions for a device.
 *
 * @param dev A pointer to the FIDO device to set the transport functions for.
 * @param transport The transport functions to set.
 */
void fido_dev_set_transport(fido_dev_t *dev, const fido_dev_transport_t *transport) {
    dev->transport = *transport;
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
    // fido_cbor_info_t    *info = NULL;
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

    /*
    // TODO: later
    if (fido_dev_is_fido2(dev)) {
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

    if (fido_dev_is_fido2(dev) && info != NULL) {
        dev->maxmsgsize = fido_cbor_info_maxmsgsiz(info);
        fido_log_debug("%s: FIDO_MAXMSG=%d, maxmsgsiz=%lu", __func__,
            FIDO_MAXMSG, (unsigned long)dev->maxmsgsize);
    }
    */

    r = FIDO_OK;
fail:
    // fido_cbor_info_free(&info);

    if (r != FIDO_OK) {
        dev->io.close(dev->io_handle);
        dev->io_handle = NULL;
    }

    return (r);
}

/**
 * @brief Open a FIDO device.
 *
 * Initializes the connection and makes it ready to communicate with.
 *
 * @param dev A pointer to the FIDO device to be opened.
 * @return int A FIDO_ERR
 */
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

/**
 * @brief Close a FIDO device.
 * 
 * Closes the connection to the device.
 *
 * @param dev A pointer to the FIDO device to be closed.
 * @return int A FIDO_ERR
 */
int fido_dev_close(fido_dev_t * dev) {
    if (dev->io.close == NULL) {
        fido_log_debug("%s: device without close function", __func__);
        return FIDO_ERR_INVALID_ARGUMENT;
    }
    dev->io.close(dev->io_handle);
    dev->io_handle = NULL;

    return FIDO_OK;
}
