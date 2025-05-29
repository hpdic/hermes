// context.hpp — Global OpenFHE BFV Context Interface
// Author: Dongfang Zhao (dzhao@cs.washington.edu)
// Institution: University of Washington
// Last Updated: May 29, 2025

#pragma once
#include "openfhe.h"

namespace hermes::crypto {

using namespace lbcrypto;

// Returns a globally shared BFV CryptoContext
CryptoContext<DCRTPoly> &getBfvContext();

// Returns a globally shared BFV KeyPair (public + secret key)
KeyPair<DCRTPoly> &getBfvKeypair();

} // namespace hermes::crypto