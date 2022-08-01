#######################################
# NFC example

add_executable(nfc nfc.c)
target_link_libraries(nfc ${PRODUCT_NAME})

#######################################
# FIDO2 authenticator simulator example

add_executable(nfc_simulator nfc_simulator.c)
target_link_libraries(nfc_simulator ${PRODUCT_NAME})
