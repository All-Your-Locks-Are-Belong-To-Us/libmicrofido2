/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <zephyr.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>

static struct device* dev;

int setup_pin() {
    dev = device_get_binding("GPIO_0");
    gpio_pin_configure(dev, 27, GPIO_OUTPUT);
}

void pin_on() {
    gpio_pin_set(dev, 27, 1);
}

void pin_off() {
    gpio_pin_set(dev, 27, 0);
}

void delay(double ms) {
    k_sleep(K_MSEC(ms));
}
