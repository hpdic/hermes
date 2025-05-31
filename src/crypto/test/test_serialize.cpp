/*
 * File: src/crypto/test/test_serialize.cpp
 * ------------------------------------------------------------
 * HERMES FHE Serialization Test
 * This test verifies that OpenFHE keys and ciphertext
 * can be serialized and deserialized correctly using a
 * shared, reinitialized BFV context.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 29, 2025
 */

#include "context.hpp"
#include "decrypt.hpp"
#include "encrypt.hpp"
#include "keygen.hpp"
#include "serialize.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

using namespace hermes::crypto;
using namespace lbcrypto;

void writeToFile(const std::string &path, const std::string &content) {
  std::ofstream out(path, std::ios::binary);
  assert(out && "Failed to open file for writing.");
  out << content;
  out.close();
  std::cout << "    > Wrote " << content.size() << " bytes to " << path
            << std::endl;
}

std::string readFromFile(const std::string &path) {
  std::ifstream file(path, std::ios::binary);
  assert(file && "Failed to open file for reading.");
  std::stringstream buffer;
  buffer << file.rdbuf();
  std::string content = buffer.str();
  std::cout << "    > Read " << content.size() << " bytes from " << path
            << std::endl;
  return content;
}

int main() {
  std::filesystem::create_directories("tmp");

  const std::string pkPath = "tmp/publicKey.txt";
  const std::string skPath = "tmp/secretKey.txt";
  const std::string ctPath = "tmp/ciphertext.txt";

  // 1. Generate context and keys
  auto ctx = makeBfvContext();
  auto kp = generateKeypair(ctx);
  std::cout << "[1] Context and keys generated." << std::endl;

  // 2. Serialize keys and write to disk
  writeToFile(pkPath, serializePublicKey(kp.publicKey));
  writeToFile(skPath, serializeSecretKey(kp.secretKey));
  std::cout << "[2] Keys serialized." << std::endl;

  // 3. Encrypt plaintext and serialize ciphertext
  Plaintext pt = ctx->MakePackedPlaintext({100});
  std::cout << "[3] Encrypting plaintext: " << pt->GetPackedValue()[0]
            << std::endl;
  auto ct = encrypt(ctx, kp.publicKey, pt);
  writeToFile(ctPath, serializeCiphertext(ct));
  std::cout << "[3] Ciphertext serialized." << std::endl;

  // 4. Re-initialize context and deserialize all
  auto ctx2 = makeBfvContext();
  auto pk2 = deserializePublicKey(readFromFile(pkPath));
  auto sk2 = deserializeSecretKey(readFromFile(skPath));
  auto ct2 = deserializeCiphertext(readFromFile(ctPath));
  std::cout << "[4] Context and keys deserialized." << std::endl;

  // 5. Decrypt and verify
  auto pt2 = decrypt(ctx2, sk2, ct2);
  std::cout << "[5] Decrypted plaintext: " << pt2->GetPackedValue()[0]
            << std::endl;

  assert(pt2->GetPackedValue() == pt->GetPackedValue());
  std::cout << "[✓] Ciphertext roundtrip test passed." << std::endl;

  return 0;
}