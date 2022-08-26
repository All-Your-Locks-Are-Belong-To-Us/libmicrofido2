# Set this to one of the following: aes_gcm, ed25519, inflate, sha256, sha512
set(measure_algorithm aes_gcm)

#######################################
# General
cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(nrf52-libmicrofido C)

target_sources(app PRIVATE "src/${measure_algorithm}_measure.c" src/gpio.c hw_crypto/hw_crypto.c)
target_include_directories(app PRIVATE src/ hw_crypto/ clock/)

#######################################
# libmicrofido2

# Necessary for building libmicrofido2
include(ExternalProject)

# Extract the Zephyr compilation settings.
zephyr_get_include_directories_for_lang_as_string(       C includes)
zephyr_get_system_include_directories_for_lang_as_string(C system_includes)
zephyr_get_compile_definitions_for_lang_as_string(       C definitions)
zephyr_get_compile_options_for_lang_as_string(           C options)

set(external_project_cflags
"${includes} ${definitions} ${options} ${system_includes} --specs=nosys.specs"
)

# Directory settings.
set(libmicrofido2_src_dir   ${CMAKE_CURRENT_SOURCE_DIR}/../../../)
set(libmicrofido2_build_dir ${CMAKE_CURRENT_BINARY_DIR}/libmicrofido2)

set(LIBMICROFIDO2_LIB_DIR     ${libmicrofido2_build_dir})
set(LIBMICROFIDO2_INCLUDE_DIR ${libmicrofido2_src_dir}/include)

ExternalProject_Add(
libmicrofido2_project   # Name for custom target
PREFIX                  ${libmicrofido2_build_dir} # Root directory for the lib.
SOURCE_DIR              ${libmicrofido2_src_dir}
BINARY_DIR              ${libmicrofido2_build_dir}
CMAKE_ARGS              # Pass the necessary build flags.
-DCMAKE_C_FLAGS=${external_project_cflags}
-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
-DCMAKE_AR=${CMAKE_AR}
-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
INSTALL_COMMAND         "" # No installation necessary, just build it.
BUILD_BYPRODUCTS        ${LIBMICROFIDO2_LIB_DIR}/libmicrofido2.a
)

# Create a wrapper CMake library that our app can link with.
add_library(libmicrofido2_lib STATIC IMPORTED GLOBAL)
add_dependencies(
libmicrofido2_lib
libmicrofido2_project
)
set_target_properties(libmicrofido2_lib PROPERTIES IMPORTED_LOCATION             ${LIBMICROFIDO2_LIB_DIR}/libmicrofido2.a)
file(MAKE_DIRECTORY ${LIBMICROFIDO2_INCLUDE_DIR}) # Hack to make the line below work on the first download.
set_target_properties(libmicrofido2_lib PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${LIBMICROFIDO2_INCLUDE_DIR} )
target_include_directories(libmicrofido2_lib INTERFACE ${libmicrofido2_src_dir}/external/tinf/include)

# Link with libmicrofido2
target_link_libraries(app PUBLIC libmicrofido2_lib)
