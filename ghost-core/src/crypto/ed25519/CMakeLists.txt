# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# ed25519-donna: Ed25519 digital signatures (public domain, Andrew Moon)
# Vendored from https://github.com/floodyberry/ed25519-donna
#
# ed25519.c is compiled as C with custom hash/random stubs.
# ed25519_impl.cpp provides the C++ implementations that bridge
# to Bitcoin Core's CSHA512 and GetStrongRandBytes.

add_library(bitcoin_crypto_ed25519 STATIC EXCLUDE_FROM_ALL
  ed25519.c
  ed25519_impl.cpp
)

target_include_directories(bitcoin_crypto_ed25519
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

# ed25519.c is C code — set custom hash/random defines only on the C file
set_source_files_properties(ed25519.c PROPERTIES
  COMPILE_DEFINITIONS "ED25519_CUSTOMHASH;ED25519_CUSTOMRANDOM"
)

target_link_libraries(bitcoin_crypto_ed25519
  PRIVATE
    bitcoin_crypto
)
