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

#include "dev.h"

/**
 * @brief Ensure that the device is correctly set up to receive data and
 *        call the device's transport receive function.
 * 
 * @param d A pointer to the FIDO device.
 * @param cmd The CTAP command to receive data from.
 * @param buf A pointer to the destination buffer.
 * @param len The size of the destination buffer.
 * @return int FIDO_OK if the read operation was successful.
 */
int fido_rx(fido_dev_t *d, const uint8_t cmd, void *buf, const size_t len);

/**
 * @brief Ensure that the device is correctly set up to transmit data and
 *        call the device's transport transmit function.
 * 
 * @param d A pointer to the FIDO device.
 * @param cmd The CTAP command to transmit.
 * @param buf A pointer to the source buffer.
 * @param len The size of the source buffer.
 * @return int FIDO_OK if the write operation was successful.
 */
int fido_tx(fido_dev_t *d, const uint8_t cmd, const void *buf, const size_t len);
int fido_get_random(void *buf, size_t len);

/**
 * @brief Read from a given buffer, copying the data and checking for overflow.
 * 
 * @param buf A pointer to the pointer to the source buffer; value will be modified
 *          to contain the new position after reading.
 * @param len The length of the memory area pointed to by buf.
 * @param dst A pointer to the destination buffer.
 * @param count The number of bytes to read.
 * @return int FIDO_OK if the operation was successful.
 */
int fido_buf_read(const unsigned char **buf, size_t *len, void *dst, size_t count);

/**
 * @brief Write to a given buffer, copying the data and checking overflow.
 * 
 * @param buf A pointer to the pointer to the destination buffer to write to;
 *          value will be modified to contain the new position (after the written bytes).
 * @param len The length of the memory area pointed to by buf.
 * @param src The source buffer.
 * @param count The number of bytes to write.
 * @return int FIDO_OK if the operation was successful.
 */
int fido_buf_write(unsigned char **buf, size_t *len, const void *src, size_t count);
