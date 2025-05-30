/*
 * File: src/tools/gen_keys.cpp
 * ------------------------------------------------------------------------
 * HERMES Keygen Utility — Offline BFV Keypair Generator
 *
 * This standalone utility generates a default keypair for the BFV scheme
 * using OpenFHE, and saves the public and private keys to disk under:
 *
 *   - Public Key : /tmp/hermes/hermes_pub.key
 *   - Secret Key : /tmp/hermes/hermes_sec.key
 *
 * This tool is intended to be run at compile/deployment time to precompute
 * keys for use by the HERMES MySQL UDF runtime.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 30, 2025
 */

#include "context.hpp"
#include "keygen.hpp"

using namespace hermes::crypto;

int main() {
  auto ctx = makeBfvContext();
  generateKeypairAndSave(ctx); // Will save to /tmp/hermes/
  return 0;
}