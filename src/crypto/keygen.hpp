/*
 * File: src/crypto/keygen.hpp
 * -------------------------------------------------------------------
 * Provides the interface for key generation and key loading in the
 * HERMES homomorphic encryption module. This header declares functions
 * to create public/secret keypairs using OpenFHE's BFV scheme, as well
 * as helper routines to persist and reload keys from the filesystem.
 *
 * The `generateKeypairAndSave()` function writes keys to a default
 * debug directory (/tmp/hermes) for prototyping purposes. In production,
 * secure key management and controlled I/O should be used instead.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 30, 2025
 */

#pragma once

#include "openfhe.h"

#include "globals.hpp"
#include "serialize.hpp"

#include <fstream>
#include <iostream>
#include <sys/stat.h>

namespace hermes::crypto {

using lbcrypto::CryptoContext;
using lbcrypto::DCRTPoly;
using lbcrypto::KeyPair;
using lbcrypto::PrivateKey;
using lbcrypto::PublicKey;

KeyPair<DCRTPoly> generateKeypair(CryptoContext<DCRTPoly> context);

// Generate a keypair and write to /tmp/hermes/ directory
KeyPair<DCRTPoly> generateKeypairAndSave(CryptoContext<DCRTPoly> context);

PublicKey<DCRTPoly> loadPublicKey(CryptoContext<DCRTPoly> context);
PrivateKey<DCRTPoly> loadSecretKey(CryptoContext<DCRTPoly> context);

} // namespace hermes::crypto