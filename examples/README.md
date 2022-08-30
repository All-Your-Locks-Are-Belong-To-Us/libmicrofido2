# examples

This directory contains examples demonstrating the use of libmicrofido2 on different microcontrollers.

- `nfc.c` shows the setup of a FIDO device.
- `invalid_device.c` shows how errors are returned by libmicrofido2.
- `measurements/` contains files to run measurements. More info in the README.
- `esp32/` contains specific files for the ESP32 hardware platform. More info in the README.
- `nrf52/` contains specific files for the NRF52480 hardware platform. More info in the README.
- `stateless_rp` contains an example of a stateless, offline relying party. This can be used in hardware or with the provided nfc simulator (which can be executed from `nfc_simulator.c`).
