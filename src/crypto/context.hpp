/*
 * File: src/crypto/context.hpp
 * -------------------------------------------------------------------
 * Provides a minimal, consistent interface for constructing and
 * accessing the default OpenFHE BFV `CryptoContext` used in the
 * HERMES system.
 *
 * CONTEXT INITIALIZATION:
 * -------------------------------------------------------------------
 * - `makeBfvContext()` constructs a fresh BFV encryption context with
 *   pre-tuned parameters (e.g., plaintext modulus, security level).
 * - Features unrelated to encryption and homomorphic addition
 *   (e.g., ADVANCED SHE features) are disabled for efficiency.
 *
 * WHY YOU SHOULD NOT CALL `makeBfvContext()` MORE THAN ONCE:
 * -------------------------------------------------------------------
 * OpenFHE internally injects randomness (e.g., seeding for modulus
 * chains and encoding structures) during `CryptoContext` generation.
 * As a result:
 *
 *     - Two identical-looking `CryptoContext` objects from separate
 *       invocations of `makeBfvContext()` **are NOT equivalent.**
 *
 *     - Even if you use the same input parameters (e.g., modulus,
 *       depth, ring dimension), **encryption and decryption will
 *       fail** if done across incompatible contexts.
 *
 *     - This issue is especially critical when encryption is performed
 *       in one shared object (.so), and decryption in another.
 *
 *     - ❗ NEVER serialize ciphertext in one .so and attempt to
 *       decrypt it in another using its own context generator.
 *
 * SAFE CONTEXT USAGE VIA `getGC()`:
 * -------------------------------------------------------------------
 * To avoid subtle and catastrophic compatibility issues, we define
 * a global singleton accessor `getGC()` that:
 *
 *     - Internally calls `makeBfvContext()` only once.
 *     - Returns the exact same `CryptoContext` pointer across all
 *       invocations within the same shared object.
 *
 *     ✅ This guarantees safe encryption, decryption, and evaluation
 *        operations within the same binary or plugin.
 *     ❌ Do NOT rely on this working across `.so` boundaries.
 *
 * USAGE:
 *     // Safe shared access to encryption context
 *     auto ctx = hermes::crypto::getGC();
 *     auto pk  = loadPublicKey();
 *     auto pt  = ctx->MakePackedPlaintext(...);
 *     auto ct  = ctx->Encrypt(pk, pt);
 *
 * AUTHOR:
 *   Dongfang Zhao, dongfang.zhao@gmail.com
 *   Last Updated: November 9, 2025
 */

#pragma once
#include "openfhe.h"

namespace hermes::crypto {

lbcrypto::CryptoContext<lbcrypto::DCRTPoly> makeBfvContext();

// Global singleton access
lbcrypto::CryptoContext<lbcrypto::DCRTPoly> getGC();
lbcrypto::CryptoContext<lbcrypto::DCRTPoly> getGC_relin();

} // namespace hermes::crypto