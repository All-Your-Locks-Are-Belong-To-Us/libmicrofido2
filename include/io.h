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
#include <stddef.h>

/**
 * @brief A function that is called to open / initialize a FIDO device.
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
 * @param buffer The buffer to read the bytes into.
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
 * These must be implemented by the user of this library.
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
