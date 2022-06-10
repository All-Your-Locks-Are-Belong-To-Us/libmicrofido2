/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include "fido.h"
#include <string.h>

int fido_buf_read(const unsigned char **buf, size_t *len, void *dst, size_t count) {
    if (count > *len) {
        return FIDO_ERR_INVALID_ARGUMENT;
    }

    memcpy(dst, *buf, count);
    *buf += count;
    *len -= count;

    return FIDO_OK;
}

int fido_buf_write(unsigned char **buf, size_t *len, const void *src, size_t count) {
    if (count > *len) {
        return FIDO_ERR_INVALID_ARGUMENT;
    }

    memcpy(*buf, src, count);
    *buf += count;
    *len -= count;

    return FIDO_OK;
}
