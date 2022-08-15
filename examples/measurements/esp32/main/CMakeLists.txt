idf_component_register(
    SRCS "src/${CONFIG_MEASURE_ALGORITHM}_measure.c" "src/gpio.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES libmicrofido2 clock hw_crypto mbedtls driver
)
