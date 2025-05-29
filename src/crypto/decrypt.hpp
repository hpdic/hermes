/*
 * File: decrypt.hpp
 * ------------------------------------------------------------
 * HERMES Crypto Module
 * Defines the decryption interface using OpenFHE (BFV scheme).
 * Provides a function to decrypt a ciphertext into a Plaintext object.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 29, 2025
 */

#pragma once

#include "openfhe.h"

namespace hermes::crypto {

using lbcrypto::Ciphertext;
using lbcrypto::CryptoContext;
using lbcrypto::DCRTPoly;
using lbcrypto::Plaintext;
using lbcrypto::PrivateKey;

Plaintext decrypt(CryptoContext<DCRTPoly> context,
                  const PrivateKey<DCRTPoly> &sk, Ciphertext<DCRTPoly> ct);

} // namespace hermes::crypto