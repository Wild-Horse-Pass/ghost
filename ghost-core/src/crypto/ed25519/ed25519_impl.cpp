// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// C++ bridge for ed25519-donna custom hash and random implementations.
// ed25519.c is compiled as pure C with ED25519_CUSTOMHASH and ED25519_CUSTOMRANDOM,
// which causes it to call the functions declared in the custom headers.
// This file provides the C-linkage implementations using Bitcoin Core's crypto.

#include <crypto/sha512.h>
#include <random.h>

#include <cassert>
#include <cstring>
#include <span>

static_assert(sizeof(CSHA512) <= 256, "CSHA512 exceeds ed25519_hash_context opaque buffer size");

extern "C" {

struct ed25519_hash_context {
    unsigned char opaque[256];
};

void ed25519_hash_init(ed25519_hash_context* ctx)
{
    new (ctx->opaque) CSHA512();
}

void ed25519_hash_update(ed25519_hash_context* ctx, const uint8_t* in, size_t inlen)
{
    reinterpret_cast<CSHA512*>(ctx->opaque)->Write(in, inlen);
}

void ed25519_hash_final(ed25519_hash_context* ctx, uint8_t* hash)
{
    reinterpret_cast<CSHA512*>(ctx->opaque)->Finalize(hash);
}

void ed25519_hash(uint8_t* hash, const uint8_t* in, size_t inlen)
{
    CSHA512().Write(in, inlen).Finalize(hash);
}

void ed25519_randombytes_unsafe(void* p, size_t len)
{
    GetStrongRandBytes(std::span<unsigned char>(static_cast<unsigned char*>(p), len));
}

} // extern "C"
