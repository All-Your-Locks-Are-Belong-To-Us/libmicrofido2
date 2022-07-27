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

#else
// To make the examples compile, default to NOOP.
#warning GPIO does not work on this system, defaulting to nop
void setup_pin() {}
void pin_on() {}
void pin_off() {}
void delay(double ms) {}
#endif
