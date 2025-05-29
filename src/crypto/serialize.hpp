/*
 * File: serialize.hpp
 * ------------------------------------------------------------
 * HERMES Crypto Module - Serialization Interface
 * Provides interfaces to serialize/deserialize:
 * - Ciphertext (PackedEncoding)
 * - CryptoContext (BFV)
 * - Public/Private Keys (separately)
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 29, 2025
 */

#pragma once

#include "openfhe.h"
#include <string>

namespace hermes::crypto {

// Ciphertext
std::string
serializeCiphertext(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &ct);
lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
deserializeCiphertext(const std::string &data);

// Public/Private Keys
std::string
serializePublicKey(const lbcrypto::PublicKey<lbcrypto::DCRTPoly> &pk);
std::string
serializeSecretKey(const lbcrypto::PrivateKey<lbcrypto::DCRTPoly> &sk);

lbcrypto::PublicKey<lbcrypto::DCRTPoly>
deserializePublicKey(const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &ctx,
                     const std::string &data);

lbcrypto::PrivateKey<lbcrypto::DCRTPoly>
deserializeSecretKey(const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &ctx,
                     const std::string &data);

} // namespace hermes::crypto