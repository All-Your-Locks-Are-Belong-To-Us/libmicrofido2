#include "fido.h"

#include <string.h>

int fido_tx(fido_dev_t *d, const uint8_t cmd, const void *buf, const size_t len) {
    fido_log_debug("%s: dev=%p, cmd=0x%02x", __func__, (void *)d, cmd);
    fido_log_xxd(buf, len, "%s", __func__);

    if (d->io_handle == NULL || d->io.write == NULL || d->transport.tx == NULL || len > UINT16_MAX) {
        fido_log_debug("%s: invalid argument", __func__);
        return (FIDO_ERR_INVALID_ARGUMENT);
    }

    return d->transport.tx(d, cmd, buf, len);
}

int fido_rx(fido_dev_t *d, const uint8_t cmd, void *buf, const size_t len) {
    int n;
    fido_log_debug("%s: dev=%p, cmd=0x%02x", __func__, (void *)d, cmd);

    if (d->io_handle == NULL || d->io.read == NULL || d->transport.rx == NULL || len > UINT16_MAX) {
        fido_log_debug("%s: invalid argument", __func__);
        return (FIDO_ERR_INVALID_ARGUMENT);
    }

    if ((n = d->transport.rx(d, cmd, buf, len)) >= 0)
        fido_log_xxd(buf, (size_t)n, "%s", __func__);

    return n;
}
