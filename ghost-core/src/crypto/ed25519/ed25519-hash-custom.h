/*
 * Custom SHA-512 hash integration for ed25519-donna.
 * Provides C-compatible function signatures that are implemented
 * in ed25519_impl.cpp using Bitcoin Core's CSHA512.
 */

#ifndef ED25519_HASH_CUSTOM_H
#define ED25519_HASH_CUSTOM_H

#include <stddef.h>
#include <stdint.h>

/* Opaque context — sized to hold CSHA512 (see sha512.h: 8 uint64_t + 128 bytes + uint64_t = 200 bytes).
 * We over-allocate to 256 bytes for safety. */
typedef struct ed25519_hash_context {
    unsigned char opaque[256];
} ed25519_hash_context;

/* Implemented in ed25519_impl.cpp */
void ed25519_hash_init(ed25519_hash_context *ctx);
void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen);
void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash);
void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen);

#endif /* ED25519_HASH_CUSTOM_H */
