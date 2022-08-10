/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#if defined(__AVR__)

#include <avr/io.h>
#include <util/delay.h>

#define PIN PB5

void setup_pin() {
    DDRB |= _BV(PIN);
}

void pin_on() {
    PORTB |= _BV(PIN);
}

void pin_off() {
    PORTB &= ~_BV(PIN);
}

void delay(double ms) {
    for (double i = 0; i < ms; i++) {
        _delay_ms(1);
    }
}

#elif defined(__ZEPHYR__)

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

#else
// To make the examples compile, default to NOOP.
#warning GPIO does not work on this system, defaulting to nop
void setup_pin() {}
void pin_on() {}
void pin_off() {}
void delay(double ms) {}
#endif
