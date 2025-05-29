/*
 * File: encrypt.cpp
 * ------------------------------------------------------------
 * HERMES Crypto Module
 * Implements the encryption function using OpenFHE (BFV scheme).
 * Takes a plaintext and a public key, returns the corresponding ciphertext.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 29, 2025
 */

#include "encrypt.hpp"

namespace hermes::crypto {

Ciphertext<DCRTPoly> encrypt(CryptoContext<DCRTPoly> ctx,
                             const PublicKey<DCRTPoly> &pk, Plaintext pt) {
  return ctx->Encrypt(pk, pt);
}

} // namespace hermes::crypto