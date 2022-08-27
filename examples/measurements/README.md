# Measurements

This folder contains several programs to measure the energy and time it takes for the different algorithms to complete.

## Compiling for ATmega

The measurement programs are compiled automatically, when compiling the `libmicrofido2`.

## Compiling for nRF52

The examples must be compiled explicitly for the nRF52.

First, navigate to the [nrf52](./nrf52) folder.
Then, make sure to select the algorithm you want to measure in the `CMakeLists.txt` by modifying the `set(MEASURE_ALGORITHM aes_gcm)`.
Finally, the build procedure is similar to the one in the [nrf52 example](../nrf52/README.md).
To initially build the program, execute: `sudo docker run --rm -v $PWD/../../../:/libmicrofido2 nrf52-sdk west -v build -b nrf52840dk_nrf52840 -d /libmicrofido2/examples/measurements/nrf52/build /libmicrofido2/examples/measurements/nrf52`.
To build the program and flash it, execute: `docker run --rm -v $PWD/../../../:/libmicrofido2 --privileged --device=/dev/ttyACM? nrf52-sdk west flash -d /libmicrofido2/examples/measurements/nrf52/build`.

## Compiling for ESP32

The examples must be compiled explicitly for the ESP32.

First, navigate to the [esp32](./esp32/) folder.
Then, make sure to select the algorithm you want to measure in the `sdkconfig` (or using `idf.py menuconfig`).
Finally, the build procedure is similar to the one in the [esp32 example](../esp32/README.md).
Therefore, to build and flash the program execute the following command from inside the [esp32](./esp32/) folder: `docker run --rm -v $PWD/../../../:/project -w /project/examples/measurements/esp32 --device /dev/ttyUSB0 espressif/idf idf.py flash`.
