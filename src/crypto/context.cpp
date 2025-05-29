// context.cpp — Global OpenFHE BFV Context Implementation
// Author: Dongfang Zhao (dzhao@cs.washington.edu)
// Institution: University of Washington
// Last Updated: May 29, 2025

#include "context.hpp"

namespace hermes::crypto {

using namespace lbcrypto;

// Return a globally shared BFV CryptoContext
CryptoContext<DCRTPoly> &getBfvContext() {
  static CryptoContext<DCRTPoly> context = [] {
    CCParams<CryptoContextBFVRNS> params;

    // ======== Plaintext modulus setup ========
    // Ensure p ≡ 1 mod 16384 (default cyclotomic ring dimension)
    params.SetPlaintextModulus(268369921);

    // Depth, security level, and features
    params.SetMultiplicativeDepth(2);

    auto ctx = GenCryptoContext(params);
    ctx->Enable(PKE);
    ctx->Enable(LEVELEDSHE);
    ctx->Enable(ADVANCEDSHE);
    return ctx;
  }();
  return context;
}

// Return a globally shared keypair for the BFV context
KeyPair<DCRTPoly> &getBfvKeypair() {
  static KeyPair<DCRTPoly> kp = [] {
    auto &ctx = getBfvContext();
    auto keys = ctx->KeyGen();
    ctx->EvalMultKeyGen(keys.secretKey);
    ctx->EvalSumKeyGen(keys.secretKey);
    return keys;
  }();
  return kp;
}

} // namespace hermes::crypto