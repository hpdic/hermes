// keygen.hpp — OpenFHE Key Generation Interface
// Author: Dongfang Zhao (dzhao@cs.washington.edu)
// Institution: University of Washington
// Last Updated: May 29, 2025

#pragma once

#include "openfhe.h"

namespace hermes::crypto {

using lbcrypto::CryptoContext;
using lbcrypto::DCRTPoly;
using lbcrypto::KeyPair;

KeyPair<DCRTPoly> generateKeypair(CryptoContext<DCRTPoly> context);

} // namespace hermes::crypto