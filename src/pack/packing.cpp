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

#include "context.hpp"
#include "encrypt.hpp"
#include "keygen.hpp"
#include "serialize.hpp"

#include <cstring>
#include <mysql/mysql.h>
#include <mysql/udf_registration_types.h>
#include <string>
#include <vector>

using namespace hermes::crypto;
using namespace lbcrypto;

struct PackState {
  std::vector<int64_t> values;
};

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
  auto kp = generateKeypair(ctx);
  auto pt = ctx->MakePackedPlaintext(state->values);
  auto ct = encrypt(ctx, kp.publicKey, pt);

  // Serialize
  buffer = serializeCiphertext(ct);
  *length = buffer.size();
  return const_cast<char *>(buffer.c_str());
}

// Free memory
extern "C" void HERMES_PACK_CONVERT_deinit(UDF_INIT *initid) {
  delete reinterpret_cast<PackState *>(initid->ptr);
}