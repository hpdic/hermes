/*
 * File: context.cpp
 * ------------------------------------------------------------
 * HERMES Context Generator
 * Implements a canonical BFV context builder using OpenFHE.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 29, 2025
 */

#include "context.hpp"

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

CryptoContext<DCRTPoly> getGC() {
  static CryptoContext<DCRTPoly> global_ctx = makeBfvContext();
  return global_ctx;
}

}