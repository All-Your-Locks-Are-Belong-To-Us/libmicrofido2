/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include "fido.h"
#include <string.h>

void iso7816_init(iso7816_apdu_t *apdu) {
    memset(apdu, 0, sizeof(iso7816_header_t));
    // Just to be sure.
    apdu->header_copied = false;
}

void iso7816_set_content(
    iso7816_apdu_t *apdu,
    const uint8_t   class,
    const uint8_t   instruction,
    const uint8_t   p1,
    const uint8_t  *payload,
    const uint16_t  payload_len
) {
    // Copy the data before the payload.
    apdu->header = (iso7816_header_t *)(payload - sizeof(iso7816_header_t));
    memcpy(apdu->header_original, apdu->header, sizeof(iso7816_header_t));
    memset(apdu->header, 0, sizeof(iso7816_header_t));


    apdu->payload_len = payload_len;
    apdu->payload_ptr = payload;
    apdu->header->cla = class;
    apdu->header->ins = instruction;
    apdu->header->p1 = p1;
    apdu->header->lc2 = (uint8_t)((payload_len >> 8) & 0xff);
    apdu->header->lc3 = (uint8_t)(payload_len & 0xff);

    apdu->header_copied = true;
}

const unsigned char * iso7816_ptr(const iso7816_apdu_t *apdu) {
    return (const unsigned char *)&apdu->header;
}

inline size_t iso7816_len(const iso7816_apdu_t *apdu) {
    return sizeof(iso7816_apdu_t) + apdu->payload_len;
}

void iso7816_restore(iso7816_apdu_t* apdu) {
    if (!apdu->header_copied) {
        return;
    }
    memcpy(apdu->header, apdu->header_original, sizeof(iso7816_header_t));
    apdu->header_copied = false;
}
