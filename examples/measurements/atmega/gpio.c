/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

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
