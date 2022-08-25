include(../../cmake/linker-map.cmake)

function(add_measurement name)
  add_executable(${name} "common/${name}.c" common/gpio.c)
  target_include_directories(${name} PRIVATE common/)
  add_linker_map_for_target(${name})
  target_link_libraries(${name} ${PRODUCT_NAME})
endfunction()

add_measurement("aes_gcm_measure")
add_measurement("ed25519_measure")
add_measurement("sha256_measure")
add_measurement("sha512_measure")
add_measurement("inflate_measure")
