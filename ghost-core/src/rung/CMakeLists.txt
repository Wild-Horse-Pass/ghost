# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Ghost Ladder Script: typed transaction format (v3 RUNG_TX).
# Replaces raw Bitcoin Script opcodes with a typed schema where every
# witness byte must conform to a typed field — no arbitrary data possible.

add_library(bitcoin_rung STATIC EXCLUDE_FROM_ALL
  types.cpp
  serialize.cpp
  conditions.cpp
  sighash.cpp
  evaluator.cpp
  policy.cpp
  rpc.cpp
)

target_include_directories(bitcoin_rung
  PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(bitcoin_rung
  PRIVATE
    core_interface
    bitcoin_common
    bitcoin_consensus
    bitcoin_util
    univalue
)
