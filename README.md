# libmicrofido2 - Minimal FIDO2 Library for Microcontrollers

**libmicrofido2** is a minimal FIDO2 library that is designed to be used in microcontrollers.
It is heavily inspired by the [`libfido2`](https://github.com/Yubico/libfido2) and aims to have a similar API.

## Features

- **No heap allocations**: All structures are allocated on the stack.
- **Physical layer agnostic**: The transport layer is left mostly to the user, so regardless of whether you want to use USB, NFC, or any other technology you can use this library. While we implemented the base layer for NFC, this can be easily implemented for other physical layers as well.
- **Fully customizable cryptographic algorithms**: All of the cryptographic algorithms (Ed25519, AES GCM, SHA256, SHA512) can be replaced by the user entirely to enable hardware acceleration (see [examples/nrf52/hw_crypto/hw_crypto.c](examples/nrf52/hw_crypto/hw_crypto.c)).

## Limitations

- We chose the cryptographic library implementations that papers say were the fastest, as that was what mattered to us the most. However, we have not evaluated their security regarding attacks such as side-channel attacks.
- Random Number Generation is currently not implemented. ([#42](https://github.com/All-Your-Locks-Are-Belong-To-Us/libmicrofido2/issues/42))
- The large blob currently cannot be written. ([#43](https://github.com/All-Your-Locks-Are-Belong-To-Us/libmicrofido2/issues/43))
- Only a minimal subset of the CTAP 2.1 commands are supported (`authenticatorGetInfo`, `authenticatorLargeBlobs`, `authenticatorGetAssertion`).
- Only a minimal subset of cryptographic algorithms specified in the FIDO2 standard supported. For signature verification, only Ed25519 is supported.
- Variable length fields and fields with arbitrary values (like the extension field in `authenticatorGetInfo`) are not supported. Instead, these fields are parsed into statically allocatable structures (see [`info.h`](include/info.h) and [`info.c`](src/info.c) for examples of this).

## Building

The build system is based on `cmake >= 3.10`.

### Desktops

You can build the library for desktops (we tested Linux and macOS):

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_BUILD_TYPE=Debug # Or Release
make -j
```

### Using Toolchains (AVR-only)

Currently, we only provide a toolchain file for the ATmega (see [#37](https://github.com/All-Your-Locks-Are-Belong-To-Us/libmicrofido2/issues/37)).
With that, you can easily build the library as a static library as follows:

```bash
mkdir -p build && cd build
# for AVR8 Debug builds
cmake .. -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_TOOLCHAIN_FILE=../avr.toolchain -DCMAKE_BUILD_TYPE=Debug
# for AVR8 Release builds
cmake .. -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_TOOLCHAIN_FILE=../avr.toolchain -DCMAKE_BUILD_TYPE=Release
make -j
```

### Other Systems

Building the library for other systems depends on the framework you use for your microcontroller.
We provide examples for the [ESP-32 using ESP-IDF](examples/esp32/) and the [nRF52 using Zephyr](examples/nrf52/).

## Usage

We provide fairly extensive examples of using this library in the [examples](examples/) directory.
Most of the time, you'll only need to [`#include <fido.h>`](include/fido.h) as that file includes most of the others.
In case you want to overwrite the implementation of the cryptographic algorithms, also checkout the [`crypto.h`](include/crypto.h) and [`random.h`](include/random.h) files.

## Development

We are happy to receive any PRs that further improve this library.
In case you want to modify the library for your needs, checkout [`DEVELOPMENT.md`](DEVELOPMENT.md).

## Acknowledgements

This library references code from:

- [`cb0r`](https://github.com/quartzjer/cb0r), licensed under the Unlicense.
- [`libfido2`](https://github.com/Yubico/libfido2), licensed under the BSD-2-Clause license.
- [`aes-gcm`](https://github.com/anibali/aes_gcm), licensed under BSD license.
- [`tinf`](https://github.com/jibsen/tinf), licensed under zlib license.
- [`crypto-algorithms`](https://github.com/B-Con/crypto-algorithms), public domain.
- [`Monocypher`](https://github.com/LoupVaillant/Monocypher), licensed under CC-0.
