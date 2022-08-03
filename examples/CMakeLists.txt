#######################################
# NFC example

add_executable(nfc nfc.c)
target_link_options(nfc PRIVATE "-Wl,-Map=nfc.map")
target_link_libraries(nfc ${PRODUCT_NAME})

add_executable(nfc_simulator nfc_simulator.c)
target_link_options(nfc_simulator PRIVATE "-Wl,-Map=nfc.map")
target_link_libraries(nfc_simulator ${PRODUCT_NAME})

#######################################
# Test applications

add_subdirectory(measurements)
