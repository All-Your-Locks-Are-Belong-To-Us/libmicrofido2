#######################################
# General
cmake_minimum_required(VERSION 3.10)

project(libmicrofido2 C)
set(PRODUCT_NAME microfido2)

#######################################
# Compilation

add_compile_options(
    -std=gnu99
    -fstack-usage
    -ffunction-sections
    -fdata-sections
    -fshort-enums
    -Wall
    -Werror
)

if(CMAKE_BUILD_TYPE MATCHES Debug)
    add_compile_options(
        -ggdb
        -O0
    )
else()
    add_compile_options(
        -Os
    )
endif()

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

# Link the object libraries
target_link_libraries(${PRODUCT_NAME} PUBLIC aes-gcm cb0r sha256 tinf)

#######################################
# Examples
add_subdirectory(examples)
