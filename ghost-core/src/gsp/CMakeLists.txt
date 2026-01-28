# Copyright (c) 2024 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# GSP (Ghost Service Protocol) module
# Provides light wallet support via HTTP REST and WebSocket APIs

add_library(bitcoin_gsp STATIC EXCLUDE_FROM_ALL
  gsp.cpp
  gsp_auth.cpp
  gsp_wallet.cpp
  gsp_ws.cpp
)

target_compile_definitions(bitcoin_gsp
  INTERFACE
    ENABLE_GSP=1
)

target_include_directories(bitcoin_gsp
  PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(bitcoin_gsp
  PRIVATE
    core_interface
    bitcoin_common
    bitcoin_util
    univalue
    secp256k1
    $<TARGET_NAME_IF_EXISTS:libevent::core>
    $<TARGET_NAME_IF_EXISTS:libevent::extra>
    SQLite::SQLite3
)
