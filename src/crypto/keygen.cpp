// keygen.cpp — OpenFHE Key Generation Implementation
// Author: Dongfang Zhao (dzhao@cs.washington.edu)
// Institution: University of Washington
// Last Updated: May 29, 2025

#include "keygen.hpp"

namespace hermes::crypto {

KeyPair<DCRTPoly> generateKeypair(CryptoContext<DCRTPoly> context) {
  auto kp = context->KeyGen();
  context->EvalMultKeyGen(kp.secretKey);
  context->EvalSumKeyGen(kp.secretKey);
  return kp;
}

KeyPair<DCRTPoly> generateKeypairAndSave(CryptoContext<DCRTPoly> context) {

  // Ensure directory exists
  mkdir(kKeyDir.c_str(), 0755);

  KeyPair<DCRTPoly> kp = generateKeypair(context);

  std::ofstream pubout(kPubKeyPath, std::ios::binary);
  if (!pubout.is_open()) {
    std::cerr << "[ERROR] Cannot write public key to " << kPubKeyPath
              << std::endl;
    std::exit(1);
  }
  pubout << serializePublicKey(kp.publicKey);
  pubout.close();
  std::cerr << "[INFO] Public key written to " << kPubKeyPath << std::endl;

  std::ofstream secout(kSecKeyPath, std::ios::binary);
  if (!secout.is_open()) {
    std::cerr << "[ERROR] Cannot write secret key to " << kSecKeyPath
              << std::endl;
    std::exit(1);
  }
  secout << serializeSecretKey(kp.secretKey);
  secout.close();
  std::cerr << "[INFO] Secret key written to " << kSecKeyPath << std::endl;

  return kp;
}

PublicKey<DCRTPoly> loadPublicKey(CryptoContext<DCRTPoly> ctx) {
  std::ifstream in(kPubKeyPath, std::ios::binary);
  if (!in) {
    throw std::runtime_error("[loadPublicKey] Failed to open public key file.");
  }
  std::string str((std::istreambuf_iterator<char>(in)),
                  std::istreambuf_iterator<char>());
  return deserializePublicKey(ctx, str);
}

PrivateKey<DCRTPoly> loadSecretKey(CryptoContext<DCRTPoly> ctx) {
  std::ifstream in(kSecKeyPath, std::ios::binary);
  if (!in) {
    throw std::runtime_error("[loadSecretKey] Failed to open secret key file.");
  }
  std::string str((std::istreambuf_iterator<char>(in)),
                  std::istreambuf_iterator<char>());
  return deserializeSecretKey(ctx, str);
}

} // namespace hermes::crypto