/*
 * HERMES FHE Unit Test
 * ------------------------------------------------------------
 * This test verifies that the key generation process using
 * OpenFHE (BFV scheme) produces a valid public/secret keypair.
 *
 * Context and keypair setup is shared via the hermes::crypto module.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 29, 2025
 */

#include "context.hpp"
#include "keygen.hpp"
#include "openfhe.h"
#include <cassert>
#include <iostream>

using namespace hermes::crypto;
using namespace lbcrypto;

int main() {
  auto ctx = getBfvContext();     // Retrieve global BFV encryption context
  auto kp = generateKeypair(ctx); // Generate keypair

  assert(kp.publicKey && kp.secretKey);
  std::cout << "[✓] KeyPair generation passed." << std::endl;

  return 0;
}