#include "fido.h"

#include <string.h>

static void *example_open() {
    // Enable NFC-field, select device.
    return NULL;
};

static void example_close() {
    // Disable NFC-field.
}

static int example_read(void *handle, unsigned char *buf, const size_t len) {
    // Read from the selected device.
    memset(buf, 0x42, len);
    return (int)len;
}

static int example_write(void *handle, const unsigned char *buf, const size_t len) {
    // Write to the selected device.
    return (int)len;
}

static const fido_dev_io_t nfc_io = {
    .open = example_open,
    .close = example_close,
    .read = example_read,
    .write = example_write
};

int main(void) {
    fido_dev_t dev;
    if (fido_init_nfc_device(&dev, &nfc_io) != FIDO_OK) {
        while (1);
    }

    if (fido_dev_open(&dev) != FIDO_OK) {
        while (1);
    }

    // Do FIDO stuff

    if (fido_dev_close(&dev) != FIDO_OK) {
        while (1);
    }
}
