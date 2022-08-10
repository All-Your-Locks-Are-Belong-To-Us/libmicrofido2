include(../cmake/linker-map.cmake)
#######################################
# NFC example

add_executable(nfc nfc.c)
add_linker_map_for_target(nfc)
target_link_libraries(nfc ${PRODUCT_NAME})

add_executable(nfc_simulator nfc_simulator.c stateless_rp.c)
add_linker_map_for_target(nfc_simulator)
target_link_libraries(nfc_simulator ${PRODUCT_NAME})

#######################################
# Test applications

add_subdirectory(measurements)
