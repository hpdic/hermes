/*
 * File: test_decrypt.cpp
 * ------------------------------------------------------------
 * HERMES FHE Unit Test
 * This test verifies that decrypting a ciphertext returns
 * the original plaintext values correctly using OpenFHE (BFV).
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 29, 2025
 */

#include "context.hpp"
#include "decrypt.hpp"
#include "encrypt.hpp"
#include "openfhe.h"
#include <cassert>
#include <iostream>
#include <assert.h>

using namespace hermes::crypto;
using namespace lbcrypto;

int main() {
  auto context = getBfvContext();
  auto keypair = getBfvKeypair();

  Plaintext pt = context->MakePackedPlaintext({11, 22, 33});
  auto ciphertext = encrypt(context, keypair.publicKey, pt);
  Plaintext output = decrypt(context, keypair.secretKey, ciphertext);

  assert(output->GetPackedValue() == pt->GetPackedValue());
  std::cout << "[✓] Decryption test passed." << std::endl;

  return 0;
}