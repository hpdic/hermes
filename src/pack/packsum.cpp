/*
 * File: src/pack/packsum.cpp
 * ------------------------------------------------------------
 * HERMES UDFs for encrypted scalar group sum and global sum
 *
 * FUNCTIONALITY:
 * ------------------------------------------------------------
 * 1. HERMES_PACK_GROUP_SUM (Aggregate UDF)
 *    - Aggregates INT values in a SQL GROUP BY.
 *    - Computes scalar sum, encrypts using BFV, serializes.
 *    - Returns base64 ciphertext string representing local sum.
 *
 * 2. HERMES_PACK_GLOBAL_SUM (Aggregate UDF)
 *    - Aggregates base64 ciphertexts from local group sums.
 *    - Applies OpenFHE BFV homomorphic addition on ciphertexts.
 *    - Returns total sum as base64 ciphertext string.
 *
 * DEPENDENCIES:
 *   - OpenFHE v1.2.4
 *   - MySQL UDF API
 *   - Hermes crypto modules: context.hpp, encrypt.hpp, keygen.hpp,
 * serialize.hpp, base64.hpp
 *
 * AUTHOR:
 *   Dongfang Zhao (dzhao@cs.washington.edu)
 *   University of Washington
 *   Last Updated: May 31, 2025
 */

#include <cstring>
#include <mysql/mysql.h>
#include <mysql/udf_registration_types.h>
#include <sstream>
#include <string>
#include <vector>

#include "base64.hpp"
#include "context.hpp"
#include "encrypt.hpp"
#include "keygen.hpp"
#include "serialize.hpp"

using namespace hermes::crypto;
using namespace lbcrypto;

// ---------------- HERMES_PACK_GROUP_SUM --------------------

struct SumState {
  int64_t sum = 0;
};

extern "C" bool HERMES_PACK_GROUP_SUM_init(UDF_INIT *initid, UDF_ARGS *args,
                                           char *msg) {
  if (args->arg_count != 1 || args->arg_type[0] != INT_RESULT) {
    std::strcpy(msg, "HERMES_PACK_GROUP_SUM expects one INT argument.");
    return 1;
  }
  initid->ptr = reinterpret_cast<char *>(new SumState());
  initid->maybe_null = 1;
  initid->max_length = 65535;
  return 0;
}

extern "C" void HERMES_PACK_GROUP_SUM_clear(UDF_INIT *initid, char *, char *) {
  reinterpret_cast<SumState *>(initid->ptr)->sum = 0;
}

extern "C" void HERMES_PACK_GROUP_SUM_add(UDF_INIT *initid, UDF_ARGS *args,
                                          char *, char *) {
  if (!args->args[0])
    return;
  int64_t val = *reinterpret_cast<long long *>(args->args[0]);
  reinterpret_cast<SumState *>(initid->ptr)->sum += val;
}

extern "C" char *HERMES_PACK_GROUP_SUM(UDF_INIT *initid, UDF_ARGS *, char *,
                                       unsigned long *length, char *is_null,
                                       char *) {
  static std::string buffer;
  buffer.clear();

  auto *state = reinterpret_cast<SumState *>(initid->ptr);
  auto ctx = makeBfvContext();
  auto pk = loadPublicKey(ctx);
  std::vector<int64_t> v = {state->sum};
  auto pt = ctx->MakePackedPlaintext(v);
  auto ct = encrypt(ctx, pk, pt);

  buffer = encodeBase64(serializeCiphertext(ct));
  *length = buffer.size();
  return const_cast<char *>(buffer.c_str());
}

extern "C" void HERMES_PACK_GROUP_SUM_deinit(UDF_INIT *initid) {
  delete reinterpret_cast<SumState *>(initid->ptr);
}

// ---------------- HERMES_PACK_GLOBAL_SUM --------------------

struct CipherAccState {
  CryptoContext<DCRTPoly> ctx;
  Ciphertext<DCRTPoly> acc;
  bool initialized = false;
};

extern "C" bool HERMES_PACK_GLOBAL_SUM_init(UDF_INIT *initid, UDF_ARGS *args,
                                            char *msg) {
  if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
    std::strcpy(msg, "HERMES_PACK_GLOBAL_SUM expects one base64 string.");
    return 1;
  }

  auto *state = new CipherAccState();
  state->ctx = makeBfvContext();
  initid->ptr = reinterpret_cast<char *>(state);
  initid->maybe_null = 1;
  initid->max_length = 65535;
  return 0;
}

extern "C" void HERMES_PACK_GLOBAL_SUM_clear(UDF_INIT *initid, char *, char *) {
  auto *state = reinterpret_cast<CipherAccState *>(initid->ptr);
  state->acc.reset();
  state->initialized = false;
}

extern "C" void HERMES_PACK_GLOBAL_SUM_add(UDF_INIT *initid, UDF_ARGS *args,
                                           char *, char *) {
  auto *state = reinterpret_cast<CipherAccState *>(initid->ptr);
  if (!args->args[0])
    return;

  std::string encoded(args->args[0], args->lengths[0]);
  auto ct = deserializeCiphertext(decodeBase64(encoded));

  if (!state->initialized) {
    state->acc = ct;
    state->initialized = true;
  } else {
    state->acc = state->ctx->EvalAdd(state->acc, ct);
  }
}

extern "C" char *HERMES_PACK_GLOBAL_SUM(UDF_INIT *initid, UDF_ARGS *, char *,
                                        unsigned long *length, char *is_null,
                                        char *) {
  auto *state = reinterpret_cast<CipherAccState *>(initid->ptr);
  if (!state->initialized) {
    *is_null = 1;
    return nullptr;
  }

  static std::string buffer;
  buffer.clear();
  buffer = encodeBase64(serializeCiphertext(state->acc));
  *length = buffer.size();
  return const_cast<char *>(buffer.c_str());
}

extern "C" void HERMES_PACK_GLOBAL_SUM_deinit(UDF_INIT *initid) {
  delete reinterpret_cast<CipherAccState *>(initid->ptr);
}