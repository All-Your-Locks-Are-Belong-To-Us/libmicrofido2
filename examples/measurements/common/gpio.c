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

#elif defined(ESP_PLATFORM)

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_cpu.h>
#include <stdio.h>
#include <driver/gpio.h>
#include <sdkconfig.h>

#define PIN 7
#define LED_PIN 19
#define LED_PIN_MASK (1ULL << LED_PIN)
#define PIN_MASK (1ULL << PIN)

#ifdef CONFIG_LOG_CYCLE_COUNT
esp_cpu_cycle_count_t clock_cycle_start;
#endif

void setup_pin() {
    // zero-initialize the config structure.
    gpio_config_t io_conf = {
        .intr_type = GPIO_INTR_DISABLE,
        .mode = GPIO_MODE_OUTPUT,
        // set pin mask to only configure these specific pins
        .pin_bit_mask = PIN_MASK,
        .pull_down_en = 0,
        .pull_up_en = 0
    };
    gpio_config(&io_conf);

    // Disable on-board LED. Apparently, this seems to increase power consumption, so we leave it on.
    // gpio_config_t led_io_conf = {
    //     .intr_type = GPIO_INTR_DISABLE,
    //     .mode = GPIO_MODE_OUTPUT,
    //     // set pin mask to only configure these specific pins
    //     .pin_bit_mask = LED_PIN_MASK,
    //     .pull_down_en = 0,
    //     .pull_up_en = 0
    // };
    // gpio_config(&led_io_conf);
    // gpio_set_level(LED_PIN, 0);
}

void pin_on() {
    gpio_set_level(PIN, 1);
    #ifdef CONFIG_LOG_CYCLE_COUNT
    clock_cycle_start = esp_cpu_get_cycle_count();
    #endif
    // We could disable the FreeRTOS interrupts for every run, but that seems to have no effect on the overall performance.
    // taskDISABLE_INTERRUPTS();
}

void pin_off() {
    #ifdef CONFIG_LOG_CYCLE_COUNT
    esp_cpu_cycle_count_t end = esp_cpu_get_cycle_count();
    uint64_t took_cycles = end - clock_cycle_start;
    printf("took %lld cycles\n", took_cycles);
    #endif

    // taskENABLE_INTERRUPTS();
    gpio_set_level(PIN, 0);
}

void delay(double ms) {
    vTaskDelay(ms / portTICK_PERIOD_MS);
}

#else
// To make the examples compile, default to NOOP.
#warning GPIO does not work on this system, defaulting to nop
void setup_pin() {}
void pin_on() {}
void pin_off() {}
void delay(double ms) {}
#endif
