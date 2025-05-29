// keygen.cpp — OpenFHE Key Generation Implementation
// Author: Dongfang Zhao (dzhao@cs.washington.edu)
// Institution: University of Washington
// Last Updated: May 29, 2025

#include "keygen.hpp"

namespace hermes::crypto {

KeyPair<DCRTPoly> generateKeypair(CryptoContext<DCRTPoly> context) {
  auto kp = context->KeyGen();
  context->EvalMultKeyGen(kp.secretKey);
  context->EvalSumKeyGen(kp.secretKey);
  return kp;
}

} // namespace hermes::crypto