#include "fido.h"

int main(void) {
    fido_dev_t device;
    fido_dev_init(&device);
    
    // This should fail because the io and transport functions are not set for the device.
    fido_dev_open(&device);

    // Always close your devices.
    fido_dev_close(&device);
}
