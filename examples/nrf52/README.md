# nrf52-libmicrofido2 Example

A small Zephyr app for the Nordic nRF52840 Development Kit using libmicrofido2.

## Build Preparation

See the attached Dockerfile that builds a container being able to compile, flash and debug the project.
This container image can be built using the following command:

```bash
sudo DOCKER_BUILDKIT=1 docker build -t nrf52-sdk .
```

## Building, Flashing and Debugging

After connecting the Devkit to the computer, it should be shown with `lsusb` as `SEGGER J-LINK`.
It should also be found as ACM device in `/dev/ttyACM?` (*remember the number*).  
Building can be done with (run from this directory!): `sudo docker run --rm -v $PWD/../../:/libmicrofido2 nrf52-sdk west -v build -b nrf52840dk_nrf52840 -d /libmicrofido2/examples/nrf52/build /libmicrofido2/examples/nrf52`.  
Flashing can then be done with `sudo docker run --rm -v $PWD/../../:/libmicrofido2 --privileged --device=/dev/ttyACM? nrf52-sdk west flash -d /libmicrofido2/examples/nrf52/build`.  
An interactive GDB session can be started with `sudo docker run --rm -it -v $PWD/../../:/libmicrofido2 --privileged --device=/dev/ttyACM? nrf52-sdk west debug -d /libmicrofido2/examples/nrf52/build`.  
You can additionally connect to the serial console output / log via `sudo docker run --rm -it --privileged --device=/dev/ttyACM0 nrf52-sdk minicom -D /dev/ttyACM0 -b 115200`.

## Hardware Cryptography

As the nRF52840 has a Cryptocell 310 hardware cryptography co-processor, this example is able to use it.
Hardware crypto can be enabled by setting the `CONFIG_NRF_SECURITY=y` in [prj.conf](./prj.conf).
When set to `n`, software implementations will be used.
