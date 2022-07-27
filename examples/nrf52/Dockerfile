#######################################
# NRF52 SDK
FROM debian:bullseye-slim

ARG TARGETARCH

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        ccache \
        curl \
        device-tree-compiler \
        dfu-util \
        file \
        g++ \
        gcc \
        git \
        gperf \
        less \
        libsdl2-dev \
        libssl-dev \
        libxcb-icccm4 \
        libxcb-image0 \
        libxcb-keysyms1 \
        libxcb-randr0 \
        libxcb-render-util0 \
        libxcb-render0 \
        libxcb-shape0 \
        libxcb-util1 \
        libxcb-xkb1 \
        libxkbcommon-x11-0 \
        make \
        minicom \
        ninja-build \
        python3-dev \
        python3-pip \
        python3-setuptools \
        python3-tk \
        python3-wheel \
        udev \
        vim \
        wget \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install cmake
RUN wget https://github.com/Kitware/CMake/releases/download/v3.23.0/cmake-3.23.0.tar.gz && \
    tar xzf cmake-3.23.0.tar.gz && \
    rm cmake-3.23.0.tar.gz && \
    cd cmake-3.23.0 && \
    mkdir build && \
    cd build && \
    ../configure && \
    make -j $(($(nproc) - 1)) && \
    make install && \
    cd ../../ && \
    rm -r cmake-3.23.0

RUN pip3 install west
ENV PATH=$PATH:/root/.local/bin
WORKDIR /opt/nordic/ncs
RUN west init -m https://github.com/nrfconnect/sdk-nrf --mr v2.0.0 && \
    west update && \
    west zephyr-export && \
    pip3 install -r zephyr/scripts/requirements.txt && \
    pip3 install -r nrf/scripts/requirements.txt && \
    pip3 install -r bootloader/mcuboot/scripts/requirements.txt
# Zephyr SDK
RUN cd /opt/ && \
    if [ "$TARGETARCH" = "amd64" ]; then ARCHITECTURE=x86_64; elif [ "$TARGETARCH" = "arm64" ]; then ARCHITECTURE=aarch64; else ARCHITECTURE=x86_64; fi && \
    wget https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.14.2/zephyr-sdk-0.14.2_linux-${ARCHITECTURE}_minimal.tar.gz && \
    wget -O - https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.14.2/sha256.sum | shasum --check --ignore-missing && \
    tar xvf zephyr-sdk-0.14.2_linux-${ARCHITECTURE}_minimal.tar.gz && \
    rm zephyr-sdk-0.14.2_linux-${ARCHITECTURE}_minimal.tar.gz && \
    cd zephyr-sdk-0.14.2 && \
    ./setup.sh -t arm-zephyr-eabi
ENV PATH=${PATH}:/opt/zephyr-sdk-0.14.2/arm-zephyr-eabi/

# nRF command line tools (closed source >.<)
RUN cd /tmp/ && \
    wget https://www.nordicsemi.com/-/media/Software-and-other-downloads/Desktop-software/nRF-command-line-tools/sw/Versions-10-x-x/10-16-0/nrf-command-line-tools_10.16.0_${TARGETARCH}.deb && \
    dpkg -i nrf-command-line-tools_10.16.0_${TARGETARCH}.deb && \
    rm nrf-command-line-tools_10.16.0_${TARGETARCH}.deb

ARG SEGGER_JLINK_VERSION=V766g

# SEGGER JLink Tools (closed source >.<)
RUN cd /tmp && \
    if [ "$TARGETARCH" = "amd64" ]; then ARCHITECTURE=x86_64; elif [ "$TARGETARCH" = "arm64" ]; then ARCHITECTURE=arm64; else ARCHITECTURE=x86_64; fi && \
    curl -X POST -d "accept_license_agreement=accepted" https://www.segger.com/downloads/jlink/JLink_Linux_${SEGGER_JLINK_VERSION}_${ARCHITECTURE}.deb --output JLink_Linux_${SEGGER_JLINK_VERSION}_${ARCHITECTURE}.deb && \
    dpkg -i JLink_Linux_${SEGGER_JLINK_VERSION}_${ARCHITECTURE}.deb && \
    if [ "$TARGETARCH" = "amd64" ]; then ln -s /opt/SEGGER/JLink/libjlinkarm.so /opt/SEGGER/JLink/jlinkarm.so; fi && \
    rm JLink_Linux_${SEGGER_JLINK_VERSION}_${ARCHITECTURE}.deb

# TODO: udev rules.
# RUN cp ~/zephyr-sdk-0.14.2/sysroots/$(uname -m)-pokysdk-linux/usr/share/openocd/contrib/60-openocd.rules /etc/udev/rules.d && \
    # udevadm control --reload

SHELL [ "bash", "-c" ]
