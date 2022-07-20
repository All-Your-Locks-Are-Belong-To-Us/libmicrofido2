#######################################
# General
cmake_minimum_required(VERSION 3.10)

project(libmicrofido2 C)
set(PRODUCT_NAME microfido2)

#######################################
# Compilation

set(CMAKE_C_FLAGS_RELEASE "-Os")
set(CMAKE_C_FLAGS_DEBUG "-ggdb -O0")

add_compile_options(
    -std=gnu99
    -fstack-usage
    -ffunction-sections
    -fdata-sections
    -fshort-enums
    -Wall
)

file(GLOB SRC_FILES "src/*.c") # Load all files in src folder

add_definitions(
    -D_FIDO_INTERNAL
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
add_library(${PRODUCT_NAME} STATIC ${SRC_FILES})

#######################################
# External libraries

# Add AES GCM library
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/aes_gcm)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/aes_gcm/include)

# Add cb0r library
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/cb0r)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/cb0r/include)

# Add SHA256 library
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/sha256)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/sha256/include)

# Add tinf library
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/tinf)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/tinf/include)

# Add Monocypher library
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/Monocypher)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/Monocypher/include)
# Always use -Os, even if it is a debug build, because Monocypher is very large and would be even larger with debug information.
target_compile_options(Monocypher PRIVATE -Os)
target_compile_definitions(Monocypher PRIVATE PERIODICALLY_RESET_WATCHDOG)

# Link the object libraries
target_link_libraries(${PRODUCT_NAME} PUBLIC aes-gcm cb0r sha256 tinf Monocypher)

#######################################
# Examples
add_subdirectory(examples)
