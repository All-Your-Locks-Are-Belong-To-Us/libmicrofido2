/*
 * Copyright (c) 2018-2022 Yubico AB. All rights reserved.
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "io.h"
#include "info.h"

/* internal device capability flags */
#define FIDO_DEV_PIN_SET        BITFIELD(0)
#define FIDO_DEV_CRED_PROT      BITFIELD(1)
#define FIDO_DEV_CREDMAN        BITFIELD(2)
#define FIDO_DEV_PIN_PROTOCOL_1 BITFIELD(3)
#define FIDO_DEV_PIN_PROTOCOL_2 BITFIELD(4)
#define FIDO_DEV_UV_SET         BITFIELD(5)
#define FIDO_DEV_TOKEN_PERMS    BITFIELD(6)
#define FIDO_DEV_LARGE_BLOB     BITFIELD(7)
#define FIDO_DEV_LARGE_BLOB_KEY BITFIELD(8)
typedef uint16_t fido_dev_flag_t;

typedef struct __attribute__((packed)) fido_ctap_info {
    uint64_t nonce;    // echoed nonce
    uint8_t  protocol; // ctaphid protocol id
    uint8_t  major;    // major version number
    uint8_t  minor;    // minor version number
    uint8_t  build;    // build version number
    uint8_t  flags;    // capabilities flags; see FIDO_CAP_*
} fido_ctap_info_t;

typedef struct fido_dev {
    fido_dev_io_t           io;         // I/O functions (raw)
    void                    *io_handle; // I/O handle
    fido_dev_transport_t    transport;  // transport functions
    size_t                  rx_len;     // length of HID input reports
    size_t                  tx_len;     // length of HID output reports
    uint64_t                nonce;      // nonce used for this device
    fido_ctap_info_t        attr;       // device attributes
    fido_dev_flag_t         flags;      // flags for the device (indicating special capabilities)
    uint64_t                maxmsgsize; // maximum message size
} fido_dev_t;

/**
 * @brief Initialize a FIDO device.
 *
 * Brings the device structure into a known state, resetting everything.
 *
 * @param dev A pointer to the uninitialized FIDO device.
 */
void fido_dev_init(fido_dev_t *dev);

/**
 * @brief Set the I/O functions for a device.
 *
 * @param dev A pointer to the FIDO device to set the I/O functions for.
 * @param io The I/O functions to set.
 */
void fido_dev_set_io(fido_dev_t *dev, const fido_dev_io_t *io);

/**
 * @brief Set the transport functions for a device.
 *
 * @param dev A pointer to the FIDO device to set the transport functions for.
 * @param transport The transport functions to set.
 */
void fido_dev_set_transport(fido_dev_t *dev, const fido_dev_transport_t *transport);

/**
 * @brief Open a FIDO device.
 *
 * Initializes the connection and makes it ready for communication.
 *
 * @param dev A pointer to the FIDO device to be opened.
 * @return intFIDO_OK when the operation was successful.
 */
int fido_dev_open(fido_dev_t *dev);

/**
 * @brief Close a FIDO device.
 * 
 * Closes the connection to the device.
 *
 * @param dev A pointer to the FIDO device to be closed.
 * @return int FIDO_OK when the operation was successful.
 */
int fido_dev_close(fido_dev_t *dev);

/**
 * @brief Test whether a device is FIDO-capable.
 *
 * @param dev A pointer to the device to check.
 */
bool fido_dev_is_fido(fido_dev_t *dev);

/**
 * @brief Retrieve information about a device.
 * 
 * @param dev A pointer to the device to retrieve information for.
 * @param ci A pointer to the information structure to store the retrieved info in.
 * @return int FIDO_OK if operation was successful.
 */
int fido_dev_get_cbor_info_wait(fido_dev_t *dev, fido_cbor_info_t *ci);
