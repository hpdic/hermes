/*
 * File: context.cpp
 * ------------------------------------------------------------
 * HERMES Context Generator
 * Implements a canonical BFV context builder using OpenFHE.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 29, 2025
 */

#include "context.hpp"

using namespace lbcrypto;

namespace hermes::crypto {

CryptoContext<DCRTPoly> makeBfvContext() {
  CCParams<CryptoContextBFVRNS> params;
  params.SetPlaintextModulus(65537);
  params.SetSecurityLevel(HEStd_128_classic);
  params.SetMultiplicativeDepth(2);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(params);

  cc->Enable(PKESchemeFeature::PKE);
  cc->Enable(PKESchemeFeature::KEYSWITCH);
  cc->Enable(PKESchemeFeature::LEVELEDSHE);
  cc->Enable(PKESchemeFeature::ADVANCEDSHE);

  return cc;
}

}