/*
 * File: packing.cpp
 * ------------------------------------------------------------
 * HERMES Aggregate UDF: HERMES_PACK_CONVERT
 *
 * This UDF aggregates multiple integer values in a group,
 * encodes them into a BFV packed plaintext using OpenFHE,
 * encrypts the plaintext, serializes the ciphertext,
 * and returns it as a LONGTEXT string.
 *
 * Usage Example:
 *   INSERT INTO packed_cipher
 *   SELECT group_id, HERMES_PACK_CONVERT(salary)
 *   FROM group_test
 *   GROUP BY group_id;
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 29, 2025
 */

#include <cstring>
#include <mysql/mysql.h>
#include <mysql/udf_registration_types.h>
#include <string>
#include <vector>

#include "context.hpp"
#include "encrypt.hpp"
#include "keygen.hpp"
#include "serialize.hpp"
#include "base64.hpp"

using hermes::crypto::decodeBase64;
using hermes::crypto::encodeBase64;

using namespace hermes::crypto;
using namespace lbcrypto;

struct PackState {
  std::vector<int64_t> values;
};

/*
 * HERMES_DEC_VECTOR_BFV
 * ------------------------------------------------------------
 * UDF: Decrypts a base64-encoded ciphertext and returns the
 * packed plaintext vector as a comma-separated string.
 *
 * Usage:
 *   SELECT HERMES_DEC_VECTOR_BFV(base64_ct);
 *
 * Returns:
 *   Comma-separated integer string like "1000,2000,1500"
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: 2025-05-29
 */

extern "C" bool HERMES_DEC_VECTOR_BFV_init(UDF_INIT *initid, UDF_ARGS *args, char *msg) {
  if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
    std::strcpy(msg, "HERMES_DEC_VECTOR_BFV expects one base64 string.");
    return 1;
  }
  initid->maybe_null = 1;
  initid->max_length = 65535;
  initid->ptr = nullptr; // for output buffer

  return 0;
}

extern "C" char *HERMES_DEC_VECTOR_BFV(UDF_INIT *initid, UDF_ARGS *args,
                                       char *result, unsigned long *length,
                                       char *is_null, char *error) {
  if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
    *is_null = 1;
    *error = 1;
    return nullptr;
  }

  try {
    std::string encoded(args->args[0], args->lengths[0]);
    std::cerr << "[UDF] Input length: " << encoded.size() << std::endl;

    std::string decoded = decodeBase64(encoded);
    if (decoded.empty()) {
      std::cerr << "[UDF] Decoded base64 string is empty.\n";
      *is_null = 1;
      *error = 1;
      return nullptr;
    }    
    
    auto ctx = hermes::crypto::makeBfvContext();

    std::ifstream skf(kSecKeyPath, std::ios::binary);
    if (!skf) {
      std::cerr << "[UDF] Failed to open secret key at " << kSecKeyPath << std::endl;
      *is_null = 1;
      *error = 1;
      return nullptr;
    }
    std::string sk_str((std::istreambuf_iterator<char>(skf)),
                       std::istreambuf_iterator<char>());
    auto sk = hermes::crypto::deserializeSecretKey(ctx, sk_str);
    std::cerr << "[UDF] Secret key loaded." << std::endl;

    auto ct = hermes::crypto::deserializeCiphertext(decoded);
    Plaintext pt;
    ctx->Decrypt(sk, ct, &pt);
    pt->SetLength(ctx->GetEncodingParams()->GetBatchSize());
    auto values = pt->GetPackedValue();

    std::cerr << "[UDF] Decrypted vector size: " << values.size() << std::endl;
    if (values.empty()) {
      std::cerr << "[UDF] Empty plaintext!" << std::endl;
      *is_null = 1;
      *error = 1;
      return nullptr;
    }

    // TODO: HPDIC: If you want to return a single value, you can uncomment the following line:
    // and comment out the loop below.
    std::string resultStr = std::to_string(values[0]);
    // std::ostringstream oss;
    // for (size_t i = 0; i < values.size(); ++i) {
    //   if (i > 0)
    //     oss << ",";
    //   oss << values[i];
    // }
    // std::string resultStr = oss.str();

  // Debug print value
    std::cerr << "[UDF] First plaintext slot: " << resultStr << std::endl;
    std::cerr << "[UDF] resultStr length: " << resultStr.length() << std::endl;

    char *out = static_cast<char *>(malloc(resultStr.size() + 1));
    if (!out) {
      std::cerr << "[UDF] malloc failed" << std::endl;
      *is_null = 1;
      *error = 1;
      return nullptr;
    }
    std::memcpy(out, resultStr.data(), resultStr.size());
    out[resultStr.size()] = '\0';
    *length = resultStr.size();
    initid->ptr = out; // Let MySQL manage this buffer

    std::cerr << "[UDF] Returning string: " << out << std::endl;
    std::cerr << "[UDF] Output length: " << *length << std::endl;

    return out;

  } catch (const std::exception &e) {
    std::cerr << "[UDF] Exception: " << e.what() << std::endl;
    *is_null = 1;
    *error = 1;
    return nullptr;
  } catch (...) {
    std::cerr << "[UDF] Unknown error occurred." << std::endl;
    *is_null = 1;
    *error = 1;
    return nullptr;
  }
}

extern "C" void HERMES_DEC_VECTOR_BFV_deinit(UDF_INIT *initid) {
  if (initid->ptr) {
    free(initid->ptr);
    initid->ptr = nullptr;
  }
}

// UDF initialization
extern "C" bool HERMES_PACK_CONVERT_init(UDF_INIT *initid, UDF_ARGS *args,
                                         char *message) {
  if (args->arg_count != 1 || args->arg_type[0] != INT_RESULT) {
    strcpy(message, "HERMES_PACK_CONVERT() expects a single INT argument.");
    return true;
  }

  initid->maybe_null = 0;
  initid->max_length = 1024 * 1024; // up to 1MB
  initid->ptr = reinterpret_cast<char*>(new PackState());    // custom aggregation buffer
  return false;
}

// Reset buffer for each GROUP
extern "C" void HERMES_PACK_CONVERT_clear(UDF_INIT *initid, char *is_null,
                                          char *error) {
  auto *state = reinterpret_cast<PackState *>(initid->ptr);
  state->values.clear();
}

// Add each value in the GROUP
extern "C" void HERMES_PACK_CONVERT_add(UDF_INIT *initid, UDF_ARGS *args,
                                        char *is_null, char *error) {
  auto *state = reinterpret_cast<PackState *>(initid->ptr);
  if (!args->args[0])
    return; // skip NULL
  int64_t val = *reinterpret_cast<long long *>(args->args[0]);
  state->values.push_back(val);
}

// Final aggregation result: serialize ciphertext
extern "C" char *HERMES_PACK_CONVERT(UDF_INIT *initid, UDF_ARGS *args,
                                     char *result, unsigned long *length,
                                     char *is_null, char *error) {
  auto *state = reinterpret_cast<PackState *>(initid->ptr);
  if (state->values.empty()) {
    *is_null = 1;
    return nullptr;
  }

  static std::string buffer; // shared buffer
  buffer.clear();

  // Encrypt
  auto ctx = makeBfvContext();
  auto pk = loadPublicKey(ctx);
  auto sk = loadSecretKey(ctx);
  auto pt = ctx->MakePackedPlaintext(state->values);
  auto ct = encrypt(ctx, pk, pt);
  // Serialize keys to disk (for debug/demo only)
  std::ofstream pubout(kPubKeyPath, std::ios::binary);
  if (!pubout.is_open()) {
    std::cerr << "[ERROR] Failed to open public key file for writing.\n";
  } else {
    pubout << hermes::crypto::serializePublicKey(pk);
    pubout.close();
    std::cerr << "[INFO] Public key written successfully.\n";
  }
  std::ofstream secout(kSecKeyPath, std::ios::binary);
  if (!secout.is_open()) {
    std::cerr << "[ERROR] Failed to open secret key file for writing.\n";
  } else {
    secout << hermes::crypto::serializeSecretKey(sk);
    secout.close();
    std::cerr << "[INFO] Secret key written successfully.\n";
  }

  // Serialize
  buffer = encodeBase64(serializeCiphertext(ct));
  *length = buffer.size();
  return const_cast<char *>(buffer.c_str());
}

// Free memory
extern "C" void HERMES_PACK_CONVERT_deinit(UDF_INIT *initid) {
  delete reinterpret_cast<PackState *>(initid->ptr);
}