/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "error.h"
#include "param.h"

/**
 * @brief A function that will be called to open / initialize a FIDO device.
 *
 * @return A pointer / handle to the device. This will be passed to the other I/O functions.
 */
typedef void *fido_dev_io_open_t();

/**
 * @brief Function for closing and deinitializing a previously opened device.
 *
 * @param handle A handle previously returned by the device open function.
 */
typedef void  fido_dev_io_close_t(void *handle);

/**
 * @brief Read raw bytes from the FIDO device.
 *
 * @param handle A handle previously returned by the device open function.
 * @param buffer The buffer to read the bytes in to.
 * @param len The length of the buffer / the number of bytes to read.
 * @return The number of bytes read.
 */
typedef int   fido_dev_io_read_t(void *handle, unsigned char *buffer, const size_t len);

/**
 * @brief Write raw bytes to the FIDO device.
 *
 * @param handle A handle previously returned by the device open function.
 * @param buffer The buffer of bytes to write to the device.
 * @param len The length of the buffer.
 * @return The number of bytes written.
 */
typedef int   fido_dev_io_write_t(void *handle, const unsigned char *buffer, size_t len);

struct fido_dev;
typedef int   fido_dev_rx_t(struct fido_dev *, const uint8_t, unsigned char *, const size_t);
typedef int   fido_dev_tx_t(struct fido_dev *, const uint8_t, const unsigned char *, const size_t);

/**
 * @brief I/O functions for accessing FIDO devices.
 *
 * They must be implemented by the user of this library.
 */
typedef struct fido_dev_io {
    fido_dev_io_open_t  *open;
    fido_dev_io_close_t *close;
    fido_dev_io_read_t  *read;
    fido_dev_io_write_t *write;
} fido_dev_io_t;

typedef struct fido_dev_transport {
    fido_dev_rx_t *rx;
    fido_dev_tx_t *tx;
} fido_dev_transport_t;

#define fido_log_debug(...) do {} while(0);
#define fido_log_xxd(...) do {} while(0);

typedef struct fido_opt_array {
    char **name;
    bool *value;
    size_t len;
} fido_opt_array_t;

typedef struct fido_str_array {
    char **ptr;
    size_t len;
} fido_str_array_t;

typedef struct fido_byte_array {
    uint8_t *ptr;
    size_t len;
} fido_byte_array_t;

typedef struct fido_algo {
    char *type;
    int cose;
} fido_algo_t;

typedef struct fido_algo_array {
    fido_algo_t *ptr;
    size_t len;
} fido_algo_array_t;

typedef struct fido_cbor_info {
    fido_str_array_t  versions;       // supported versions: fido2|u2f
    fido_str_array_t  extensions;     // list of supported extensions
    fido_str_array_t  transports;     // list of supported transports
    unsigned char     aaguid[16];     // aaguid
    fido_opt_array_t  options;        // list of supported options
    uint64_t          maxmsgsiz;      // maximum message size
    fido_byte_array_t protocols;      // supported pin protocols
    fido_algo_array_t algorithms;     // list of supported algorithms
    uint64_t          maxcredcntlst;  // max credentials in list
    uint64_t          maxcredidlen;   // max credential ID length
    uint64_t          fwversion;      // firmware version
    uint64_t          maxcredbloblen; // max credBlob length
    uint64_t          maxlargeblob;   // max largeBlob array length
} fido_cbor_info_t;

typedef struct __attribute__((packed)) fido_ctap_info {
    uint64_t nonce;    // echoed nonce
    uint32_t cid;      // channel id TODO: weg?
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

int fido_rx(fido_dev_t *, const uint8_t, void *, const size_t);
int fido_tx(fido_dev_t *, const uint8_t, const void *, const size_t);
int fido_get_random(void *, size_t);

/**
 * @brief Initialize a FIDO device.
 *
 * Brings the device structure into a known state, resetting everything.
 *
 * @param dev A pointer to the uninitialized FIDO device.
 */
void fido_dev_init(fido_dev_t *);

/**
 * @brief Set the I/O functions for a device.
 *
 * @param dev A pointer to the FIDO device to set the I/O functions for.
 * @param io The I/O functions to set.
 */
void fido_dev_set_io(fido_dev_t *, const fido_dev_io_t *);

/**
 * @brief Set the transport functions for a device.
 *
 * @param dev A pointer to the FIDO device to set the transport functions for.
 * @param transport The transport functions to set.
 */
void fido_dev_set_transport(fido_dev_t *, const fido_dev_transport_t *);

/**
 * @brief Open a FIDO device.
 *
 * Initializes the connection and makes it ready to communicate with.
 *
 * @param dev A pointer to the FIDO device to be opened.
 * @return int A FIDO_ERR
 */
int fido_dev_open(fido_dev_t *);

/**
 * @brief Close a FIDO device.
 * 
 * Closes the connection to the device.
 *
 * @param dev A pointer to the FIDO device to be closed.
 * @return int A FIDO_ERR
 */
int fido_dev_close(fido_dev_t *);
