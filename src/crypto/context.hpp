/*
 * File: src/crypto/context.hpp
 * -------------------------------------------------------------------
 * Provides a minimal, clean interface for constructing the default
 * BFV CryptoContext used throughout the HERMES system. The context
 * includes standard OpenFHE parameters and disables unused features
 * (e.g., SHE, ADVANCED) for performance and simplicity.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 30, 2025
 */

#pragma once
#include "openfhe.h"

namespace hermes::crypto {

lbcrypto::CryptoContext<lbcrypto::DCRTPoly> makeBfvContext();

} // namespace hermes::crypto