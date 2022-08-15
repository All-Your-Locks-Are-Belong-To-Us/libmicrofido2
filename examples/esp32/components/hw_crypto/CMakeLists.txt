idf_component_register(
    SRCS "hw_crypto.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES libmicrofido2 mbedtls
)
