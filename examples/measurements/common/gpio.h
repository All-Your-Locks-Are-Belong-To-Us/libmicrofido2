/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#pragma once

/**
 * @brief Setup the logical PPK2 output pin.
 */
void setup_pin();

/**
 * @brief Turn the logical PPK2 output pin on.
 */
void pin_on();

/**
 * @brief Turn the logical PPK2 output pin off.
 */
void pin_off();

/**
 * @brief Delay program execution by given milliseconds.
 *
 * @param ms Milliseconds to delay program execution
 */
void delay(double ms);
