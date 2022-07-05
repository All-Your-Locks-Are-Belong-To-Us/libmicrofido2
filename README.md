# libmicrofido2 - Minimal FIDO2 Library for Microcontrollers

The **libmicrofido2** is a minimal FIDO2 library that is designed to be used in microcontrollers.
It is heavily inspired by the [`libfido2`](https://github.com/Yubico/libfido2) and aims to have a similar API.

## Building

You need to install `cmake >= 3.10`. Having done that you can do:

```bash
mkdir -p build && cd build
# for AVR8 Debug builds
cmake .. -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_TOOLCHAIN_FILE=../avr.toolchain -DCMAKE_BUILD_TYPE=Debug
# for AVR8 Release builds
cmake .. -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_TOOLCHAIN_FILE=../avr.toolchain -DCMAKE_BUILD_TYPE=Release
```

## Acknowledgements

This library uses code from:

- [`cb0r`](https://github.com/quartzjer/cb0r), licensed under the Unlicense.
- [`libfido2`](https://github.com/Yubico/libfido2), licensed under the BSD-2-Clause license.
- [`aes-gcm`](https://github.com/anibali/aes_gcm), licensed under BSD license.
- [`tinf`](https://github.com/jibsen/tinf), licensed under zlib license.
- [`crypto-algorithms`](https://github.com/B-Con/crypto-algorithms), public domain.
- [`Monocypher`](https://github.com/LoupVaillant/Monocypher), licensed under CC-0.
