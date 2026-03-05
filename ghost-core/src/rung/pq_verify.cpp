// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/pq_verify.h>

#include <logging.h>

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

namespace rung {

bool HasPQSupport()
{
#ifdef HAVE_LIBOQS
    return true;
#else
    return false;
#endif
}

bool VerifyPQSignature(RungScheme scheme,
                       std::span<const uint8_t> sig,
                       std::span<const uint8_t> msg,
                       std::span<const uint8_t> pubkey)
{
#ifdef HAVE_LIBOQS
    const char* alg_name = nullptr;
    switch (scheme) {
    case RungScheme::FALCON512:   alg_name = OQS_SIG_alg_falcon_512; break;
    case RungScheme::FALCON1024:  alg_name = OQS_SIG_alg_falcon_1024; break;
    case RungScheme::DILITHIUM3:  alg_name = OQS_SIG_alg_dilithium_3; break;
    case RungScheme::SPHINCS_SHA: alg_name = OQS_SIG_alg_sphincs_sha2_256f_simple; break;
    default:
        return false;
    }

    OQS_SIG* oqs_sig = OQS_SIG_new(alg_name);
    if (!oqs_sig) {
        LogPrintf("PQ: Failed to initialize algorithm %s\n", alg_name);
        return false;
    }

    OQS_STATUS result = OQS_SIG_verify(oqs_sig, msg.data(), msg.size(),
                                         sig.data(), sig.size(), pubkey.data());
    OQS_SIG_free(oqs_sig);
    return (result == OQS_SUCCESS);
#else
    (void)scheme;
    (void)sig;
    (void)msg;
    (void)pubkey;
    LogPrintf("PQ: Post-quantum signature verification unavailable (liboqs not compiled in)\n");
    return false;
#endif
}

} // namespace rung
