/*
 * File: context.cpp
 * ------------------------------------------------------------
 * HERMES Context Generator
 * Implements a canonical BFV context builder using OpenFHE.
 *
 * FUNCTIONALITY:
 * ------------------------------------------------------------
 * This module provides context construction and shared instance access
 * for all BFV-based UDFs in the HERMES system. All crypto operations—
 * including encryption, decryption, homomorphic addition, multiplication,
 * and slot-level operations—depend on this unified context.
 *
 * WHY GALOIS KEYS ARE LOADED:
 * ------------------------------------------------------------
 * OpenFHE's EvalAtIndex (i.e., rotation) operations require precomputed
 * Galois keys. These keys are tied to the secret key and must be loaded
 * explicitly into the CryptoContext in advance.
 *
 * In HERMES, we support encrypted vector manipulation that involves:
 *   - Selective masking (via slot-wise plaintext vectors)
 *   - Rotation-based re-indexing (e.g., insertion, deletion)
 * These rely on `EvalAtIndex`, which internally uses the Galois key set.
 *
 * The function `loadContextWithGaloisKeysOnly()` ensures that:
 *   - The base context is generated deterministically.
 *   - The Galois keys are loaded from a shared file (under /tmp/hermes/).
 *   - No other keys (e.g., EvalMult or EvalSum) are needed for rotation.
 *
 * DESIGN NOTE:
 * ------------------------------------------------------------
 *   - `getGC()` exposes a shared static context with Galois keys.
 *   - This context is used in *all* UDFs that require rotation or packed
 *     encoding manipulation.
 *   - This design avoids key mismatch errors and simplifies key reuse
 *     across `.so` boundaries.
 *
 * DEPENDENCIES:
 *   - OpenFHE v1.2.4
 *   - Galois key file must be generated using EvalAtIndexKeyGen and saved
 *     under the path defined by `kGaloisKeyPath` (see globals.hpp).
 *
 * AUTHOR:
 *   Dongfang Zhao (dzhao@cs.washington.edu)
 *   University of Washington
 *   Last Updated: June 1, 2025
 */

#include "context.hpp"
#include "globals.hpp"
#include "keygen.hpp"

using namespace lbcrypto;

namespace hermes::crypto {

CryptoContext<DCRTPoly> makeBfvContext() {
  CCParams<CryptoContextBFVRNS> params;

  /**
   * ======================= Plaintext Modulus Notes ========================
   *
   * OpenFHE's BFV scheme uses a cyclotomic polynomial ring of order m,
   * where m is typically a power of 2. If not explicitly set, OpenFHE
   * defaults to:
   *
   *     m = 2^14 = 16384
   *
   * To ensure encoding succeeds, the plaintext modulus p must satisfy:
   *
   *     (p - 1) % m == 0     i.e.,   p ≡ 1 mod m
   *
   * If this condition is not met, OpenFHE will throw runtime exceptions:
   *
   *     SetParams_2n(): The modulus value must be prime.
   *     RootOfUnity(): The modulus and ring dimension must be compatible.
   *
   * The value 268,369,921 is a safe prime satisfying:
   *
   *     268,369,921 ≡ 1 mod 16384
   *
   * This supports signed plaintext integers up to approximately ±134 million.
   *
   * ⚠️  If you change the ring dimension m, you must select a new p such
   *     that p ≡ 1 mod m.
   */
  params.SetPlaintextModulus(268369921); // safe default for m = 16384
  // params.SetPlaintextModulus(65537);

  params.SetSecurityLevel(HEStd_128_classic);
  params.SetMultiplicativeDepth(2);

  // params.SetRingDim(16384); // matching plaintext modulus
  // params.SetScalingModSize(59);
  // params.SetBatchSize(8192);     // seed 可自定义

  CryptoContext<DCRTPoly> cc = GenCryptoContext(params);

  cc->Enable(PKESchemeFeature::PKE);
  // cc->Enable(PKESchemeFeature::KEYSWITCH);
  cc->Enable(PKESchemeFeature::LEVELEDSHE);
  cc->Enable(PKESchemeFeature::ADVANCEDSHE);

  return cc;
}

// CryptoContext<DCRTPoly> getGC() {
//   static CryptoContext<DCRTPoly> global_ctx = makeBfvContext();
//   return global_ctx;
// }

CryptoContext<DCRTPoly> loadContextWithGaloisKeysOnly() {
  auto cc = makeBfvContext(); // Creat context without Galois keys

  // 1. Load and register EvalAutomorphismKeys
  std::ifstream galin(kGaloisKeyPath, std::ios::binary);
  if (!galin.is_open()) {
    std::cerr << "[ERROR] Cannot open Galois key file: " << kGaloisKeyPath
              << "\n";
    std::exit(1);
  }

  if (!cc->DeserializeEvalAutomorphismKey(galin, SerType::BINARY)) {
    std::cerr << "[ERROR] Failed to deserialize Galois keys.\n";
    std::exit(1);
  }

  galin.close();
  return cc;
}

CryptoContext<DCRTPoly> getGC() {
  static CryptoContext<DCRTPoly> global_ctx = loadContextWithGaloisKeysOnly();
  return global_ctx;
}

} // namespace hermes::crypto
// EOF: context.cpp
// ------------------------------------------------------------------------