# libmicrofido2 on ESP32

A small ESP-IDF app for the ESP32 using the libmicrofido2.

## Preparation

1. Pull the [IDF Docker Image](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/tools/idf-docker-image.html): `docker pull espressif/idf`
1. Alternatively, if you don't want to use Docker, [install ESP-IDF manually](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/#installation).

## Building

1. Run `docker run --rm -v $PWD/../../:/project -w /project/examples/esp32 espressif/idf idf.py build`.
1. To get an interactive shell, run `docker run --rm -v $PWD/../../:/project -w /project/examples/esp32 -it espressif/idf`.

## Flashing

1. Connect the ESP32 to your computer and find its device node at `/dev/ttyUSBX` (note the value of `X` and replace it in the following command).
1. Run `docker run --rm -v $PWD/../../:/project -w /project/examples/esp32 --device /dev/ttyUSBX espressif/idf idf.py flash`.

## Hardware Cryptography

By default, hardware accelerated AES, partially AES-GCM, SHA-256, and SHA-512 are enabled.
As of now (2022), the ESP32C3 does not have hardware support for Ed25519.
To disable these, set `CONFIG_USE_HW_CRYPTO=n` in your `sdkconfig`.
