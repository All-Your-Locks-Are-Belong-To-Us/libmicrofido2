#pragma once

#include <stdint.h>

#include "io.h"

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
