/*
 * File: src/pack/packing.cpp
 * ------------------------------------------------------------
 * HERMES UDFs for Packed Ciphertext Encoding and Decryption
 *
 * This file defines two MySQL UDFs for batch encrypting and
 * decrypting homomorphically encrypted integer vectors:
 *
 *   1. HERMES_PACK_CONVERT(val)
 *      - Aggregate UDF that collects integers from a GROUP BY group,
 *        packs them into a plaintext vector, encrypts with BFV,
 *        and returns a Base64-encoded ciphertext.
 *
 *   2. HERMES_DEC_VECTOR(ciphertext_base64, logical_length)
 *      - Scalar UDF that decrypts a packed ciphertext and returns
 *        a comma-separated string of the first `logical_length`
 *        plaintext values (excluding padded zeros).
 *
 * AUTHOR:
 *   Dongfang Zhao (dzhao@cs.washington.edu)
 *   University of Washington
 *   Last Updated: June 1, 2025
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

extern "C" bool HERMES_DEC_VECTOR_init(UDF_INIT *initid, UDF_ARGS *args,
                                           char *msg) {
  if (args->arg_count != 2 || args->arg_type[0] != STRING_RESULT ||
      args->arg_type[1] != INT_RESULT) {
    std::strcpy(
        msg, "HERMES_DEC_VECTOR expects (base64_ciphertext, int_length)");
    return 1;
  }

  initid->maybe_null = 1;
  initid->max_length = 65535;
  initid->ptr = nullptr;
  return 0;
}

extern "C" char *HERMES_DEC_VECTOR(UDF_INIT *initid, UDF_ARGS *args,
                                       char *result, unsigned long *length,
                                       char *is_null, char *error) {
  try {
    std::string encoded(args->args[0], args->lengths[0]);
    int64_t vec_len = *reinterpret_cast<long long *>(args->args[1]);

    if (vec_len <= 0) {
      *is_null = 1;
      *error = 1;
      return nullptr;
    }

    std::string decoded = decodeBase64(encoded);
    if (decoded.empty()) {
      *is_null = 1;
      *error = 1;
      return nullptr;
    }

    auto ctx = getGC();
    auto sk = loadSecretKey();
    auto ct = deserializeCiphertext(decoded);
    Plaintext pt;
    ctx->Decrypt(sk, ct, &pt);
    auto values = pt->GetPackedValue();

    if (values.size() < static_cast<size_t>(vec_len)) {
      *is_null = 1;
      *error = 1;
      return nullptr;
    }

    std::ostringstream oss;
    for (int64_t i = 0; i < vec_len; ++i) {
      if (i > 0)
        oss << ",";
      oss << values[i];
    }

    std::string resultStr = oss.str();
    char *out = static_cast<char *>(malloc(resultStr.size() + 1));
    if (!out) {
      *is_null = 1;
      *error = 1;
      return nullptr;
    }

    std::memcpy(out, resultStr.data(), resultStr.size());
    out[resultStr.size()] = '\0';
    *length = resultStr.size();
    initid->ptr = out;
    return out;

  } catch (...) {
    *is_null = 1;
    *error = 1;
    return nullptr;
  }
}

extern "C" void HERMES_DEC_VECTOR_deinit(UDF_INIT *initid) {
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

/*
 * HERMES_PACK_CONVERT
 * ------------------------------------------------------------
 * Aggregate UDF: Encrypts and returns a packed ciphertext.
 *
 * This function aggregates a group of integer values, encodes
 * them using OpenFHE’s BFV scheme into a packed plaintext, then
 * encrypts the plaintext and serializes the ciphertext.
 *
 * NEW DESIGN (as of June 1, 2025):
 * ------------------------------------------------------------
 * - The plaintext is now explicitly padded to the full OpenFHE
 *   batch size (i.e., all unused slots are filled with zeros).
 * - We no longer store the logical length in slot[0]. Instead,
 *   the tuple count is stored in a separate SQL column.
 *
 * This design simplifies ciphertext logic and enables future
 * slot-wise insertion without structural ambiguity.
 *
 * RETURN:
 *   A Base64-encoded ciphertext string containing the encrypted
 *   packed plaintext (fully padded to batch size).
 *
 * AUTHOR:
 *   Dongfang Zhao (dzhao@cs.washington.edu)
 *   University of Washington
 *   Last Updated: June 1, 2025
 */
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
  auto ctx = getGC();
  auto pk = loadPublicKey();

  size_t slot_capacity = ctx->GetEncodingParams()->GetBatchSize();
  std::vector<int64_t> padded_values(slot_capacity, 0);

  for (size_t i = 0; i < state->values.size() && i < slot_capacity; ++i) {
    padded_values[i] = state->values[i];
  }

  auto pt = ctx->MakePackedPlaintext(padded_values);
  pt->SetLength(slot_capacity); // ensure all slots are available

  auto ct = encrypt(ctx, pk, pt);

  // Serialize
  buffer = encodeBase64(serializeCiphertext(ct));
  *length = buffer.size();
  return const_cast<char *>(buffer.c_str());
}

// Free memory
extern "C" void HERMES_PACK_CONVERT_deinit(UDF_INIT *initid) {
  delete reinterpret_cast<PackState *>(initid->ptr);
}