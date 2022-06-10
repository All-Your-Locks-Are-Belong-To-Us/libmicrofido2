#pragma once

#include <stdint.h>

#include "dev.h"

int fido_rx(fido_dev_t *d, const uint8_t cmd, void *buf, const size_t len);
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
 * @return int FIDO_OK when the operation was successful.
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
 * @return int FIDO_OK when the operation was successful.
 */
int fido_buf_write(unsigned char **buf, size_t *len, const void *src, size_t count);
