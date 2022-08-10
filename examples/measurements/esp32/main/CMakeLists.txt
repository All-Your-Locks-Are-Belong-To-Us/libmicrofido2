idf_component_register(
    SRCS "src/${CONFIG_MEASURE_ALGORITHM}_measure.c" "src/gpio.c"
    INCLUDE_DIRS "src/"
    PRIV_REQUIRES libmicrofido2 driver
)
