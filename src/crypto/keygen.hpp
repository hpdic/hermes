// keygen.hpp — OpenFHE Key Generation Interface
// Author: Dongfang Zhao (dzhao@cs.washington.edu)
// Institution: University of Washington
// Last Updated: May 29, 2025

#pragma once

#include "openfhe.h"

#include "globals.hpp"
#include "serialize.hpp"

#include <fstream>
#include <iostream>
#include <sys/stat.h>

namespace hermes::crypto {

using lbcrypto::CryptoContext;
using lbcrypto::DCRTPoly;
using lbcrypto::KeyPair;
using lbcrypto::PrivateKey;
using lbcrypto::PublicKey;

KeyPair<DCRTPoly> generateKeypair(CryptoContext<DCRTPoly> context);

// Generate a keypair and write to /tmp/hermes/ directory
KeyPair<DCRTPoly> generateKeypairAndSave(CryptoContext<DCRTPoly> context);

PublicKey<DCRTPoly> loadPublicKey(CryptoContext<DCRTPoly> context);
PrivateKey<DCRTPoly> loadSecretKey(CryptoContext<DCRTPoly> context);

} // namespace hermes::crypto