# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Ghost Tor mode: embedded Tor subprocess management

add_library(bitcoin_tor STATIC EXCLUDE_FROM_ALL
  tor_process.cpp
)

target_include_directories(bitcoin_tor
  PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(bitcoin_tor
  PRIVATE
    core_interface
    bitcoin_common
    bitcoin_util
)
