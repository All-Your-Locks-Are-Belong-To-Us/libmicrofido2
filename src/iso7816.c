/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include "fido.h"
#include "iso7816.h"
#include <string.h>

void iso7816_init(
    iso7816_apdu_t *apdu,
    const uint8_t   class,
    const uint8_t   instruction,
    const uint8_t   p1,
    const uint8_t  *payload,
    const uint16_t  payload_len
) {
    memset(apdu, 0, sizeof(iso7816_apdu_t));

    apdu->payload_len = payload_len;
    apdu->payload_ptr = payload;
    apdu->header.cla = class;
    apdu->header.ins = instruction;
    apdu->header.p1 = p1;
}

void iso7816_init_from_bytes(
    iso7816_apdu_t *apdu,
    const uint8_t  *buffer,
    const uint16_t  buffer_len
) {
    memcpy(&apdu->header, buffer, sizeof(iso7816_header_t));
    apdu->payload_len = buffer_len - sizeof(iso7816_header_t);
    apdu->payload_ptr = buffer + sizeof(iso7816_header_t);
}
