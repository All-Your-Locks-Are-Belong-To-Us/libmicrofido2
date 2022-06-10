/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#pragma once

#include <stdint.h>
#include <stdlib.h>


typedef struct __attribute__((packed)) iso7816_header {
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint8_t lc1;
    uint8_t lc2;
    uint8_t lc3;
} iso7816_header_t;

#define ISO7816_APDU_BUFFER_SIZE(x) (sizeof(iso7816_header_t) + x)

typedef struct iso7816_apdu {
    uint16_t            payload_len;
    iso7816_header_t   *header;
    const uint8_t      *payload_ptr;
    // This is a hacky hack hack.
    // Because we do not want to copy the payload,
    // we "abuse" the data before the payload.
    // We store the data that was there (probably some return pointers, other stack data)
    // and replace it with the header.
    // When the apdu is deallocated, we restore the data.
    uint8_t             header_original[sizeof(iso7816_header_t)];
    bool                header_copied;
} iso7816_apdu_t;

void iso7816_init(iso7816_apdu_t *);
void iso7816_set_content(iso7816_apdu_t *, const uint8_t, const uint8_t, const uint8_t, const uint8_t*, const uint16_t);
const unsigned char *iso7816_ptr(const iso7816_apdu_t *);
size_t iso7816_len(const iso7816_apdu_t *);
void iso7816_restore(iso7816_apdu_t*);
