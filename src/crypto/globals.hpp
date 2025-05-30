#pragma once

#include <string>

namespace hermes::crypto {

// Default directory for key storage (for debug/demo use only)
inline const std::string kKeyDir = "/tmp/hermes";
inline const std::string kPubKeyPath = kKeyDir + "/hermes_pub.key";
inline const std::string kSecKeyPath = kKeyDir + "/hermes_sec.key";

} // namespace hermes::crypto