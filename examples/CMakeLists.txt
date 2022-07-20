#######################################
# NFC example

add_executable(nfc nfc.c)
target_link_libraries(nfc ${PRODUCT_NAME})

#######################################
# FIDO2 authenticator simulator example

add_executable(simulator simulator.c)
target_link_libraries(simulator ${PRODUCT_NAME})
