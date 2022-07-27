#######################################
# NFC example

add_executable(nfc nfc.c)
target_link_options(nfc PRIVATE "-Wl,-Map=nfc.map")
target_link_libraries(nfc ${PRODUCT_NAME})

#######################################
# FIDO2 authenticator simulator example

add_executable(simulator simulator.c)
target_link_options(simulator PRIVATE "-Wl,-Map=simulator.map")
target_link_libraries(simulator ${PRODUCT_NAME})

#######################################
# Baumann et al example application
add_executable(example_baumann_et_al example_baumann_et_al.c)
target_link_options(example_baumann_et_al PRIVATE "-Wl,-Map=example_baumann_et_al.map")
target_link_libraries(example_baumann_et_al ${PRODUCT_NAME})

#######################################
# Test applications

add_executable(aes_gcm_example aes_gcm_example.c)
target_link_options(aes_gcm_example PRIVATE "-Wl,-Map=aes_gcm_example.map")
target_link_libraries(aes_gcm_example ${PRODUCT_NAME})
