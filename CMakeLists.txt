#######################################
# General
cmake_minimum_required(VERSION 3.10)

project(libmicrofido2 C)
set(PRODUCT_NAME microfido2)

#######################################
# Compilation

set(CMAKE_C_FLAGS_RELEASE "-O3")
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

option(USE_SOFTWARE_CRYPTO_AES_GCM_ENCRYPT "include software AES GCM encryption" OFF)
if(NOT USE_SOFTWARE_CRYPTO_AES_GCM_ENCRYPT)
    add_compile_definitions(NO_SOFTWARE_CRYPTO_AES_GCM_ENCRYPT)
endif()

option(USE_SOFTWARE_CRYPTO_AES_GCM_DECRYPT "include software AES GCM decryption" ON)
if(NOT USE_SOFTWARE_CRYPTO_AES_GCM_DECRYPT)
    add_compile_definitions(NO_SOFTWARE_CRYPTO_AES_GCM_DECRYPT)
endif()

option(USE_SOFTWARE_CRYPTO_ED25519_SIGN "include software ed25519 signature generation" OFF)
if(NOT USE_SOFTWARE_CRYPTO_ED25519_SIGN)
    add_compile_definitions(NO_SOFTWARE_CRYPTO_ED25519_SIGN)
endif()

option(USE_SOFTWARE_CRYPTO_ED25519_VERIFY "include software ed25519 signature verification" ON)
if(NOT USE_SOFTWARE_CRYPTO_ED25519_VERIFY)
    add_compile_definitions(NO_SOFTWARE_CRYPTO_ED25519_VERIFY)
endif()

option(USE_SOFTWARE_CRYPTO_SHA256 "include software SHA256" ON)
if(NOT USE_SOFTWARE_CRYPTO_SHA256)
    add_compile_definitions(NO_SOFTWARE_CRYPTO_SHA256)
endif()

option(USE_SOFTWARE_CRYPTO_SHA512 "include software SHA512" OFF)
if(NOT USE_SOFTWARE_CRYPTO_SHA512)
    add_compile_definitions(NO_SOFTWARE_CRYPTO_SHA512)
endif()

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
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Use -Os in debug build because otherwise it wouldn't fit on AVR.
    target_compile_options(Monocypher PRIVATE -Os)
endif()
target_compile_definitions(Monocypher PRIVATE PERIODICALLY_RESET_WATCHDOG)

# Link the object libraries
target_link_libraries(${PRODUCT_NAME} PUBLIC aes-gcm cb0r sha256 tinf Monocypher)

#######################################
# Examples
add_subdirectory(examples)
