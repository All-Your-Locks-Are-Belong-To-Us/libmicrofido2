#pragma once

#include <stddef.h>

#include "fido.h"

/**
 * @brief Initialize a FIDO device to use NFC.
 *
 * @param device The device to initialize.
 * @param io I/O operations that are used to do raw interactions.
 *           Must be provided as some kind of HAL.
 */
int fido_init_nfc_device(fido_dev_t *device, const fido_dev_io_t *io);
