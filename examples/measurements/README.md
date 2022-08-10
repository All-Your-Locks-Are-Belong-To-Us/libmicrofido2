# Measurements

This folder contains several programs to measure the energy and time it takes for the different algorithms to complete.

## Compiling for ATmega

The measurement programs are compiled automatically, when compiling the `libmicrofido2`.

## Compiling for nRF52

The examples must be compiled explicitly for the nRF52.

First, navigate to the [nrf52](./nrf52) folder.
Then, make sure to select the algorithm you want to measure in the `CMakeLists.txt` by modifying the `set(MEASURE_ALGORITHM aes_gcm)`.
Finally, the build procedure is similar to the one in the [nrf52 example](../nrf52/README.md).
To build and flash the program, execute: `docker run --rm -v $PWD/../../../:/libmicrofido2 --privileged --device=/dev/ttyACM? nrf52-sdk west flash -d /libmicrofido2/examples/measurements/nrf52/build`.
