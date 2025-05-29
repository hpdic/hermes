#pragma once
#include "openfhe.h"

namespace hermes::crypto {

lbcrypto::CryptoContext<lbcrypto::DCRTPoly> makeBfvContext();

} // namespace hermes::crypto