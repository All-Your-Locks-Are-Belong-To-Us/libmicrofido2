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
} iso7816_header_t;

#define ISO7816_APDU_BUFFER_SIZE(x) (sizeof(iso7816_header_t) + x)

typedef struct iso7816_apdu {
    uint16_t            payload_len;
    iso7816_header_t    header;
    const uint8_t      *payload_ptr;
} iso7816_apdu_t;

/**
 * @brief Initialize an ISO7816 APDU.
 * 
 * @param apdu A pointer to the APDU to initialize.
 * @param instruction An ISO7816-4 Instruction.
 * @param p1 The p1 field (see ISO78164, second edition, 5.1).
 * @param payload A pointer to the buffer containing the payload.
 * @param payload_len The length of the payload.
 */
void iso7816_init(
    iso7816_apdu_t *apdu,
    const uint8_t   class,
    const uint8_t   instruction,
    const uint8_t   p1,
    const uint8_t  *payload,
    const uint16_t  payload_len
);

/**
 * @brief Read an ISO7816 APDU from a buffer.
 * 
 * @param apdu The APDU to initialize.
 * @param buffer A pointer to the buffer to read from.
 * @param buffer_len The length of the buffer.
 */
void iso7816_init_from_bytes(
    iso7816_apdu_t *apdu,
    const uint8_t  *buffer,
    const uint16_t  buffer_len
);
