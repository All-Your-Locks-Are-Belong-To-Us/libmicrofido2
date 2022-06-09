#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct fido_opt_array {
    char **name;
    bool *value;
    size_t len;
} fido_opt_array_t;

typedef struct fido_str_array {
    char **ptr;
    size_t len;
} fido_str_array_t;

typedef struct fido_byte_array {
    uint8_t *ptr;
    size_t len;
} fido_byte_array_t;

typedef struct fido_algo {
    char *type;
    int cose;
} fido_algo_t;

typedef struct fido_algo_array {
    fido_algo_t *ptr;
    size_t len;
} fido_algo_array_t;
