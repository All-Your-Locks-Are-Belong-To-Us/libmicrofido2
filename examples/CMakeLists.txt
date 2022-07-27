#######################################
# NFC example

add_executable(nfc nfc.c)
target_link_options(nfc PRIVATE "-Wl,-Map=nfc.map")
target_link_libraries(nfc ${PRODUCT_NAME})

#######################################
# Test applications

add_executable(aes_gcm_example aes_gcm_example.c)
target_link_options(aes_gcm_example PRIVATE "-Wl,-Map=aes_gcm_example.map")
target_link_libraries(aes_gcm_example ${PRODUCT_NAME})
