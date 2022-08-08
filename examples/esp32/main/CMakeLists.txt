idf_component_register(
    SRCS "esp32-libmicrofido2.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES libmicrofido2 mbedtls
)
