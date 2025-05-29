/*
 * File: serialize.cpp
 * ------------------------------------------------------------
 * HERMES Crypto Module - Serialization Implementation
 * Implements routines to serialize/deserialize:
 * - Ciphertext
 * - CryptoContext
 * - PublicKey and SecretKey separately
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 29, 2025
 */

#include "serialize.hpp"
#include <sstream>

using namespace lbcrypto;

namespace hermes::crypto {

// ------------------------
// Ciphertext Serialization
// ------------------------

std::string serializeCiphertext(const Ciphertext<DCRTPoly> &ct) {
  std::ostringstream oss;
  Serial::Serialize(ct, oss, SerType::BINARY);
  return oss.str();
}

Ciphertext<DCRTPoly> deserializeCiphertext(const std::string &s) {
  std::istringstream iss(s);
  Ciphertext<DCRTPoly> ct;
  Serial::Deserialize(ct, iss, SerType::BINARY);
  return ct;
}

// ------------------------
// Key Serialization (Split)
// ------------------------

std::string serializePublicKey(const PublicKey<DCRTPoly> &pk) {
  std::ostringstream oss;
  Serial::Serialize(pk, oss, SerType::BINARY);
  return oss.str();
}

std::string serializeSecretKey(const PrivateKey<DCRTPoly> &sk) {
  std::ostringstream oss;
  Serial::Serialize(sk, oss, SerType::BINARY);
  return oss.str();
}

PublicKey<DCRTPoly> deserializePublicKey(const CryptoContext<DCRTPoly> &ctx,
                                         const std::string &s) {
  std::istringstream iss(s);
  PublicKey<DCRTPoly> pk;
  Serial::Deserialize(pk, iss, SerType::BINARY);
  return pk;
}

PrivateKey<DCRTPoly> deserializeSecretKey(const CryptoContext<DCRTPoly> &ctx,
                                          const std::string &s) {
  std::istringstream iss(s);
  PrivateKey<DCRTPoly> sk;
  Serial::Deserialize(sk, iss, SerType::BINARY);
  return sk;
}

} // namespace hermes::crypto