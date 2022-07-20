# Since we are wrapping the library inside a component,
# the component has to be registered first:
idf_component_register()

#######################################
# libmicrofido2

# Necessary for building libmicrofido2
include(ExternalProject)

# Directory settings.
set(libmicrofido2_src_dir   ${CMAKE_CURRENT_SOURCE_DIR}/../../../..)
set(libmicrofido2_build_dir ${CMAKE_CURRENT_BINARY_DIR}/libmicrofido2)

set(LIBMICROFIDO2_LIB_DIR     ${libmicrofido2_build_dir})
set(LIBMICROFIDO2_INCLUDE_DIR ${libmicrofido2_src_dir}/include)

ExternalProject_Add(
  libmicrofido2_project   # Name for custom target
  PREFIX                  ${libmicrofido2_build_dir} # Root directory for the lib.
  SOURCE_DIR              ${libmicrofido2_src_dir}
  BINARY_DIR              ${libmicrofido2_build_dir}
  CMAKE_ARGS              # Pass the necessary build flags.
  # TODO: Don't hardcode this here
  -DCMAKE_C_FLAGS=-DESP_PLATFORM
  -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
  -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
  INSTALL_COMMAND         "" # No installation necessary, just build it.
  BUILD_BYPRODUCTS        ${LIBMICROFIDO2_LIB_DIR}/libmicrofido2.a

#   GIT_REPOSITORY          https://github.com/All-Your-Locks-Are-Belong-To-Us/libmicrofido2
#   GIT_SUBMODULES_RECURSE  TRUE # Also use the submodules.
#   GIT_PROGRESS            TRUE # Show some progress.
#   GIT_TAG                 db5c60eb7a6c1666157b62aa143d35f40da6b351 # The commit hash.
)

# Create a wrapper CMake library that our app can link with.
add_library(libmicrofido2_lib STATIC IMPORTED GLOBAL)
add_dependencies(
  libmicrofido2_lib
  libmicrofido2_project
)
set_target_properties(libmicrofido2_lib PROPERTIES IMPORTED_LOCATION             ${LIBMICROFIDO2_LIB_DIR}/libmicrofido2.a)

set_target_properties(libmicrofido2_lib PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${LIBMICROFIDO2_INCLUDE_DIR})

# Link with libmicrofido2
target_link_libraries(${COMPONENT_LIB} INTERFACE libmicrofido2_lib)
