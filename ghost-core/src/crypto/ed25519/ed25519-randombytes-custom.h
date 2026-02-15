/*
 * Custom random bytes integration for ed25519-donna.
 * Provides C-compatible function signature that is implemented
 * in ed25519_impl.cpp using Bitcoin Core's GetStrongRandBytes.
 */

#ifndef ED25519_RANDOMBYTES_CUSTOM_H
#define ED25519_RANDOMBYTES_CUSTOM_H

#include <stddef.h>

/* Implemented in ed25519_impl.cpp */
void ED25519_FN(ed25519_randombytes_unsafe) (void *p, size_t len);

#endif /* ED25519_RANDOMBYTES_CUSTOM_H */
