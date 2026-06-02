cmake_minimum_required(VERSION 3.10)
project(signal_nif C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find libsodium with better error handling
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

if(NOT SODIUM_FOUND)
    message(FATAL_ERROR "libsodium not found. Please install libsodium-dev (Ubuntu/Debian) or libsodium (macOS)")
endif()

# Use pkg-config results
include_directories(${SODIUM_INCLUDE_DIRS})
link_directories(${SODIUM_LIBRARY_DIRS})
set(SODIUM_LIBRARIES ${SODIUM_LIBRARIES})

# OpenSSL provides AES-256-CBC (libsodium does not). Used by the Signal-spec
# DR AEAD construction (AES-256-CBC + HMAC-SHA-256 + PKCS#7).
# On macOS with Homebrew openssl@3 is keg-only; CMake's FindOpenSSL needs a
# hint when the brew install isn't on the default search path.
if(APPLE AND NOT DEFINED OPENSSL_ROOT_DIR)
    execute_process(
        COMMAND brew --prefix openssl@3
        OUTPUT_VARIABLE _BREW_OPENSSL_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE _BREW_OPENSSL_RESULT
    )
    if(_BREW_OPENSSL_RESULT EQUAL 0)
        set(OPENSSL_ROOT_DIR "${_BREW_OPENSSL_PREFIX}")
    endif()
endif()
find_package(OpenSSL REQUIRED)

# Detect Erlang include directory automatically
execute_process(
  COMMAND erl -noshell -eval "io:format(\"~s\", [code:root_dir()]), halt()."
  OUTPUT_VARIABLE ERLANG_ROOT
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Try different possible Erlang include paths
set(ERLANG_INCLUDE_DIR "${ERLANG_ROOT}/usr/include")
if(NOT EXISTS "${ERLANG_INCLUDE_DIR}")
  set(ERLANG_INCLUDE_DIR "${ERLANG_ROOT}/include")
endif()

# Add include directories
include_directories(${ERLANG_INCLUDE_DIR})

# Add source files - use the fixed version
add_library(signal_nif SHARED
    signal_nif.c
)

# Add the libsignal_protocol_nif library
add_library(libsignal_protocol_nif SHARED
    libsignal_protocol_nif.c
    dr.c
    dr_proto.c
    keys.c
    pksm.c
    session.c
)

# Link libsodium to all libraries; OpenSSL only needed by the DR AEAD in
# libsignal_protocol_nif.
target_link_libraries(signal_nif ${SODIUM_LIBRARIES})
target_link_libraries(libsignal_protocol_nif ${SODIUM_LIBRARIES} OpenSSL::Crypto)

# Remove explicit erl_nif linking; use dynamic lookup on macOS
if(APPLE)
    target_link_options(signal_nif PRIVATE "-undefined" "dynamic_lookup")
    target_link_options(libsignal_protocol_nif PRIVATE "-undefined" "dynamic_lookup")
endif()

# Set output directory and name for signal_nif
set_target_properties(signal_nif PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../priv"
    OUTPUT_NAME "signal_nif"
    PREFIX ""  # Remove the "lib" prefix
)

# Set output directory and name for libsignal_protocol_nif
set_target_properties(libsignal_protocol_nif PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../priv"
    OUTPUT_NAME "libsignal_protocol_nif"
    PREFIX ""  # Remove the "lib" prefix
)

# Set compile flags based on platform.
# Note: BEAM expects .so for NIFs on macOS too, so APPLE is intentionally
# folded into the UNIX branch — do not split out a .dylib case.
if(UNIX)
    set_target_properties(signal_nif PROPERTIES
        SUFFIX ".so"
    )
    set_target_properties(libsignal_protocol_nif PROPERTIES
        SUFFIX ".so"
    )
elseif(WIN32)
    set_target_properties(signal_nif PROPERTIES
        SUFFIX ".dll"
    )
    set_target_properties(libsignal_protocol_nif PROPERTIES
        SUFFIX ".dll"
    )
endif()