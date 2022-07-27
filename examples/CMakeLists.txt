#######################################
# NFC example

add_executable(nfc nfc.c)
target_link_options(nfc PRIVATE "-Wl,-Map=nfc.map")
target_link_libraries(nfc ${PRODUCT_NAME})
