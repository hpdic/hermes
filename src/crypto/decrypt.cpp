/*
 * File: decrypt.cpp
 * ------------------------------------------------------------
 * HERMES Crypto Module
 * Implements decryption using OpenFHE (BFV scheme).
 * Converts ciphertexts back into plaintext integers or packed vectors.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 29, 2025
 */

 #include "decrypt.hpp"

namespace hermes::crypto {

Plaintext decrypt(CryptoContext<DCRTPoly> context,
                  const PrivateKey<DCRTPoly> &sk, Ciphertext<DCRTPoly> ct) {
  Plaintext result;
  context->Decrypt(sk, ct, &result);
  result->SetLength(1); // For packed plaintexts
  return result;
}

} // namespace hermes::crypto