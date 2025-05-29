/*
 * File: test_encrypt.cpp
 * ------------------------------------------------------------
 * HERMES FHE Unit Test
 * This test verifies that encryption using OpenFHE (BFV scheme)
 * produces a valid ciphertext from a vector of integers.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 29, 2025
 */

#include "context.hpp"
#include "encrypt.hpp"
#include "openfhe.h"
#include <cassert>
#include <iostream>

using namespace hermes::crypto;
using namespace lbcrypto;

int main() {
  auto context = getBfvContext();
  auto publicKey = getBfvKeypair().publicKey;

  Plaintext pt = context->MakePackedPlaintext({42, 0, -7});
  auto ciphertext = encrypt(context, publicKey, pt);

  assert(ciphertext);
  std::cout << "[✓] Encryption test passed." << std::endl;

  return 0;
}