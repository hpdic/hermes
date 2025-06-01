/*
 * File: src/pack/packsum.cpp
 * ------------------------------------------------------------
 * HERMES UDFs for scalar encryption, encrypted group sum,
 * encrypted global sum, and local decryption (packed BFV).
 *
 * FUNCTIONALITY:
 * ------------------------------------------------------------
 * 1. HERMES_ENC_SINGULAR (Scalar UDF)
 *    - Encrypts a single integer using OpenFHE's BFV scheme.
 *    - Returns a base64-encoded ciphertext string.
 *    - Encodes the integer into slot[0] of a packed plaintext;
 *      all other slots are padded with zero.
 *
 * 2. HERMES_PACK_GROUP_SUM (Aggregate UDF)
 *    - Aggregates INT values per SQL GROUP BY.
 *    - Encrypts the resulting scalar sum as a packed plaintext.
 *    - Returns a base64-encoded ciphertext representing the local sum.
 *
 * 3. HERMES_PACK_GLOBAL_SUM (Aggregate UDF)
 *    - Aggregates encrypted group sums across departments (or other groups).
 *    - Performs homomorphic addition on ciphertexts.
 *    - Returns a base64-encoded ciphertext of the total sum.
 *
 * 4. HERMES_DEC_SINGULAR (Scalar UDF)
 *    - Decrypts a base64-encoded BFV ciphertext and returns the scalar integer.
 *    - Expects the integer to be stored in slot[0] only.
 *
 * DESIGN CONSTRAINTS:
 * ------------------------------------------------------------
 * ❗ All encryption and decryption UDFs must reside in the same `.so` file.
 *    - OpenFHE contexts are not portable across shared objects.
 *    - Even with identical encryption parameters, contexts created in
 *      different `.so` libraries will generate incompatible ciphertexts.
 *
 *    ➤ For this reason, `HERMES_ENC_SINGULAR` and `HERMES_DEC_SINGULAR`
 *      must be paired within this file. Do not attempt to decrypt in a
 *      separate plugin (e.g., singular.so) unless context reuse is guaranteed.
 *
 * WHY `getGC()` MATTERS:
 * ------------------------------------------------------------
 * - All crypto operations use a shared context provided by `getGC()`.
 * - This function ensures that encryption, aggregation, and decryption
 *   are performed under the same context instance with a consistent
 *   modulus chain and encoding configuration.
 * - Avoids undefined behavior due to context mismatch.
 *
 * IMPLEMENTATION DETAILS:
 * ------------------------------------------------------------
 * - Ciphertexts are passed between UDFs as base64-encoded strings.
 * - Internally, all ciphertexts use OpenFHE's BFV scheme with packed encoding.
 * - Memory allocations are managed via `malloc` and `initid->ptr` to avoid
 *   MySQL UDF stack overflows (especially for large ciphertexts).
 *
 * DEPENDENCIES:
 *   - OpenFHE v1.2.4
 *   - MySQL UDF API
 *   - Hermes crypto modules:
 *     - context.hpp
 *     - keygen.hpp
 *     - encrypt.hpp
 *     - serialize.hpp
 *     - base64.hpp
 *
 * AUTHOR:
 *   Dongfang Zhao (dzhao@cs.washington.edu)
 *   University of Washington
 *   Last Updated: June 1, 2025
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

extern "C" bool HERMES_ENC_SINGULAR_init(UDF_INIT *initid, UDF_ARGS *args,
                                         char *msg) {
  if (args->arg_count != 1 || args->arg_type[0] != INT_RESULT) {
    std::strcpy(msg, "HERMES_ENC_SINGULAR expects a single integer input.");
    return 1;
  }

  initid->maybe_null = 1;
  initid->max_length = 65535;
  initid->ptr = nullptr;
  return 0;
}

extern "C" char *HERMES_ENC_SINGULAR(UDF_INIT *initid, UDF_ARGS *args,
                                     char *result, unsigned long *length,
                                     char *is_null, char *error) {
  try {
    if (!args->args[0]) {
      *is_null = 1;
      *error = 1;
      return nullptr;
    }

    int64_t val = *reinterpret_cast<long long *>(args->args[0]);

    auto cc = getGC();
    if (!cc)
      throw std::runtime_error("Crypto context is null");
    size_t slot_count = cc->GetEncodingParams()->GetBatchSize();
    std::vector<int64_t> vec(slot_count, 0);
    vec[0] = val;

    auto pk = loadPublicKey();
    if (!pk)
      throw std::runtime_error("Public key is null");

    auto pt = cc->MakePackedPlaintext(vec);
    pt->SetLength(slot_count);

    auto ct = cc->Encrypt(pk, pt);
    if (!ct)
      throw std::runtime_error("Encryption returned null");

    std::string out = encodeBase64(serializeCiphertext(ct));
    char *buf = static_cast<char *>(malloc(out.size() + 1));
    if (!buf) {
      *is_null = 1;
      *error = 1;
      return nullptr;
    }

    std::memcpy(buf, out.data(), out.size());
    buf[out.size()] = '\0';
    *length = out.size();
    initid->ptr = buf;
    return buf;

  } catch (const std::exception &e) {
    std::cerr << "[UDF::HERMES_ENC_SINGULAR] Exception: " << e.what()
              << std::endl;
    *is_null = 1;
    *error = 1;
    return nullptr;
  } catch (...) {
    std::cerr << "[UDF::HERMES_ENC_SINGULAR] Unknown error" << std::endl;
    *is_null = 1;
    *error = 1;
    return nullptr;
  }
}

extern "C" void HERMES_ENC_SINGULAR_deinit(UDF_INIT *initid) {
  if (initid->ptr) {
    free(initid->ptr);
    initid->ptr = nullptr;
  }
}