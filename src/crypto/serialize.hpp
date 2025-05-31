/*
 * File: src/crypto/serialize.hpp
 * -------------------------------------------------------------------
 * Serialization interfaces for HERMES homomorphic encryption objects.
 * This module provides base64-encoded string representations of:
 *
 *   - Ciphertext<DCRTPoly> (typically using PackedEncoding)
 *   - PublicKey / PrivateKey (from OpenFHE BFV context)
 *   - CryptoContext (not exposed yet, but extensible)
 *
 * These functions enable cross-process transfer and persistent storage
 * of encryption artifacts during FHE database operations. All formats
 * are designed to be compatible with OpenFHE's serialization protocols.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 30, 2025
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
deserializePublicKey(const std::string &data);

lbcrypto::PrivateKey<lbcrypto::DCRTPoly>
deserializeSecretKey(const std::string &data);

} // namespace hermes::crypto