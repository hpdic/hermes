// File: gen_keys.cpp
// ------------------------------------------------------------
// Compile-time BFV key generation entry point
// Author: Dongfang Zhao (dzhao@cs.washington.edu)
// Institution: University of Washington
// Last Updated: May 30, 2025

#include "context.hpp"
#include "keygen.hpp"

using namespace hermes::crypto;

int main() {
  auto ctx = makeBfvContext();
  generateKeypairAndSave(ctx); // Will save to /tmp/hermes/
  return 0;
}