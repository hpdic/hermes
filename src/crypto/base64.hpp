#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace hermes::crypto {

std::string encodeBase64(const std::string &input);
std::string decodeBase64(const std::string &input);

} // namespace hermes::crypto