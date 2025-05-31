/*
 * File: src/pack/packsum.cpp
 * ------------------------------------------------------------
 * HERMES UDFs for encrypted scalar group sum, global sum, and context-bound
 * decryption.
 *
 * FUNCTIONALITY:
 * ------------------------------------------------------------
 * 1. HERMES_PACK_GROUP_SUM (Aggregate UDF)
 *    - Aggregates INT values per SQL GROUP BY.
 *    - Encrypts the resulting scalar sum using OpenFHE's BFV scheme.
 *    - Returns a base64-encoded ciphertext string representing the local sum.
 *
 * 2. HERMES_PACK_GLOBAL_SUM (Aggregate UDF)
 *    - Aggregates base64 ciphertexts across groups (e.g., via GROUP_CONCAT).
 *    - Applies homomorphic addition over all encrypted group sums.
 *    - Returns a base64-encoded ciphertext string of the global total sum.
 *
 * 3. HERMES_DEC_SINGULAR (Scalar UDF)
 *    - Decrypts a base64-encoded BFV ciphertext and returns the scalar integer.
 *    - **Must be invoked from within the same shared object (.so) as the one
 * that performed encryption.**
 *
 * WHY CAN'T WE USE THE SHARED DECRYPTION FUNCTION FROM ANOTHER .SO?
 * ------------------------------------------------------------
 * Although a similar function `HERMES_DEC_SINGULAR_BFV` is defined in
 * `src/singular/udf.cpp`,
 * **you cannot decrypt here using that version** if it's loaded from a
 * different `.so` file.
 *
 * This is because:
 *
 *   - OpenFHE's `CryptoContext` (BFV) construction includes internal randomness
 *     (e.g., in modulus chain generation, key switching matrices, and encoding
 * tables).
 *   - Even with identical input parameters, separate `.so` plugins will
 * generate **non-identical contexts**.
 *   - Ciphertexts encrypted under one context cannot be decrypted under
 * another, even if the keys look compatible.
 *
 * Therefore:
 *
 *     ❌ DO NOT call decryption UDFs across `.so` boundaries.
 *     ✅ Instead, define and invoke decryption functions *within the same .so*
 * where encryption occurred.
 *
 * WHY WE USE getGC():
 * ------------------------------------------------------------
 * To ensure that encryption and decryption within this `.so` share a
 * **consistent runtime context**, we define `getGC()` as a singleton-like
 * global accessor. This function guarantees:
 *
 *   - Only a single `CryptoContext` instance is created.
 *   - All UDFs in this `.so` use the same memory-resident context object.
 *
 * This design avoids subtle issues where different invocations of
 * `makeBfvContext()` may generate new (but incompatible) contexts, even inside
 * the same process.
 *
 * DEPENDENCIES:
 *   - OpenFHE v1.2.4
 *   - MySQL UDF API
 *   - Hermes crypto modules:
 *     - context.hpp   → Defines `getGC()` for shared BFV context.
 *     - keygen.hpp    → Loads persistent public/private keys.
 *     - encrypt.hpp   → Encrypts packed plaintext vectors.
 *     - serialize.hpp → (De)serializes ciphertext objects.
 *     - base64.hpp    → Encodes ciphertexts as base64 strings.
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
  auto ctx = getGC();
  auto pk = loadPublicKey();
  std::vector<int64_t> v = {state->sum};

  // DEBUG
  // std::cerr << "[DEBUG] v = " << v << std::endl;                                  

  auto pt = ctx->MakePackedPlaintext(v);
  pt->SetLength(1);

  // auto ct = encrypt(ctx, pk, pt);
  // buffer = encodeBase64(serializeCiphertext(ct));
  // *length = buffer.size();
  // return const_cast<char *>(buffer.c_str());

  auto ct = ctx->Encrypt(pk, pt);
  std::string encoded = encodeBase64(serializeCiphertext(ct));
  *length = encoded.size();

  auto serialized = serializeCiphertext(ct);
  auto ct2 = deserializeCiphertext(serialized);
  auto sk = loadSecretKey(); // 添加这个调试用
  Plaintext decrypted;
  ctx->Decrypt(sk, ct, &decrypted);
  decrypted->SetLength(1);
  std::cerr << "[DEBUG] roundtrip = " << decrypted->GetPackedValue()
            << std::endl;

  return strdup(encoded.c_str());
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
  state->ctx = getGC();
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

extern "C" bool HERMES_DEC_SINGULAR_init(UDF_INIT *initid, UDF_ARGS *args, char *msg) {
  if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
    std::strcpy(msg, "HERMES_DEC_SINGULAR requires one base64 string.");
    return 1;
  }
  initid->maybe_null = 1;
  return 0;
}

extern "C" long long HERMES_DEC_SINGULAR(UDF_INIT *, UDF_ARGS *args, char *is_null,
                                  char *err) {
  try {
    std::string ct_str(args->args[0], args->lengths[0]);
    auto ctx = getGC();
    auto sk = loadSecretKey();
    auto ct = deserializeCiphertext(decodeBase64(ct_str));
    Plaintext pt;
    ctx->Decrypt(sk, ct, &pt);
    pt->SetLength(1);
    auto v = pt->GetPackedValue();
    return v.empty() ? 0 : v[0];
  } catch (...) {
    *is_null = 1;
    *err = 1;
    return 0;
  }
}