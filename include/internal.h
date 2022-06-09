#pragma once

#include <stdint.h>

#include "dev.h"

int fido_rx(fido_dev_t *d, const uint8_t cmd, void *buf, const size_t len);
int fido_tx(fido_dev_t *d, const uint8_t cmd, const void *buf, const size_t len);
int fido_get_random(void *buf, size_t len);
