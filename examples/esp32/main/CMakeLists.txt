idf_component_register(
    SRCS "esp32-libmicrofido2.c" "stateless_rp/stateless_rp.c" "stateless_rp/stateless_rp_nfc_simulator.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES libmicrofido2 mbedtls
)
