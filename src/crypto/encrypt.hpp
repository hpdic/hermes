/*
 * File: encrypt.hpp
 * ------------------------------------------------------------
 * HERMES Crypto Module
 * Defines the encryption interface using OpenFHE (BFV scheme).
 * Provides a function to encrypt a plaintext using a public key.
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
using lbcrypto::PublicKey;

Ciphertext<DCRTPoly> encrypt(CryptoContext<DCRTPoly> ctx,
                             const PublicKey<DCRTPoly> &pk, Plaintext pt);

} // namespace hermes::crypto