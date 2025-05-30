/*
 * File: src/crypto/base64.hpp
 * ------------------------------------------------------------
 * HERMES Crypto Module - Base64 Encoding/Decoding Interface
 * Provides utility functions to encode and decode binary data
 * using Base64 representation.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 30, 2025
 */

#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace hermes::crypto {

std::string encodeBase64(const std::string &input);
std::string decodeBase64(const std::string &input);

} // namespace hermes::crypto