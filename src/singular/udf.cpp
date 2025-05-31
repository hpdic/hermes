/*
 * File: src/singular/udf.cpp
 * ------------------------------------------------------------------------
 * HERMES MySQL UDF Plugin (BFV, Scalar Mode — Rewritten with Pack
 * Infrastructure)
 *
 * This file defines MySQL user-defined functions (UDFs) that perform
 * homomorphic operations on singular (scalar) integers encrypted under the
 * OpenFHE BFV scheme. It has been refactored to use the shared context/key
 * infrastructure from the `hermes::crypto` module to ensure consistent
 * encryption semantics across plugins.
 *
 * Key Changes in This Version:
 *   - Uses `makeBfvContext()` from `hermes::crypto::context.cpp`
 *   - Loads keys from filesystem paths (in `tmp/hermes/`) instead of generating
 * fresh ones
 *   - Ciphertext and key serialization handled by centralized helpers
 *   - Uses packed plaintexts of length 1 for scalar encryption
 *
 * Plugin Functions:
 *   - char*      HERMES_ENC_SINGULAR_BFV(int plaintext)
 *   - long long  HERMES_DEC_SINGULAR_BFV(base64 ciphertext)
 *   - long long  HERMES_SUM_BFV(base64 ciphertexts...)     (Aggregate)
 *   - char*      HERMES_MUL_BFV(base64 ct1, base64 ct2)
 *   - char*      HERMES_MUL_SCALAR_BFV(base64 ct, scalar)
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington (HPDIC Lab)
 * Last Updated: May 31, 2025
 */

#include <cstring>
#include <iostream>
#include <mysql.h>
#include <sstream>
#include <string>
#include <vector>

#include "base64.hpp"
#include "context.hpp"
#include "decrypt.hpp"
#include "encrypt.hpp"
#include "keygen.hpp"
#include "serialize.hpp"

using namespace lbcrypto;
using hermes::crypto::decodeBase64;
using hermes::crypto::deserializeCiphertext;
using hermes::crypto::encodeBase64;
using hermes::crypto::loadPublicKey;
using hermes::crypto::loadSecretKey;
using hermes::crypto::makeBfvContext;
using hermes::crypto::serializeCiphertext;
using hermes::crypto::kPubKeyPath;
using hermes::crypto::kSecKeyPath;

extern "C" {

// ------------------- ENCRYPT -------------------

bool HERMES_ENC_SINGULAR_BFV_init(UDF_INIT *initid, UDF_ARGS *args, char *msg) {
  if (args->arg_count != 1 || args->arg_type[0] != INT_RESULT) {
    std::strcpy(msg, "HERMES_ENC_SINGULAR_BFV requires one integer.");
    return 1;
  }
  initid->maybe_null = 1;
  initid->max_length = 65535;
  return 0;
}

char *HERMES_ENC_SINGULAR_BFV(UDF_INIT *, UDF_ARGS *args, char *,
                              unsigned long *len, char *is_null, char *err) {
  try {
    int64_t val = *reinterpret_cast<long long *>(args->args[0]);
    auto ctx = makeBfvContext();
    auto pk = loadPublicKey();
    auto pt = ctx->MakePackedPlaintext({val});
    pt->SetLength(1);
    auto ct = ctx->Encrypt(pk, pt);
    std::string encoded = encodeBase64(serializeCiphertext(ct));
    *len = encoded.size();
    return strdup(encoded.c_str());
  } catch (...) {
    *is_null = 1;
    *err = 1;
    return nullptr;
  }
}

// ------------------- DECRYPT -------------------

bool HERMES_DEC_SINGULAR_BFV_init(UDF_INIT *initid, UDF_ARGS *args, char *msg) {
  if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
    std::strcpy(msg, "HERMES_DEC_SINGULAR_BFV requires one base64 string.");
    return 1;
  }
  initid->maybe_null = 1;
  return 0;
}

long long HERMES_DEC_SINGULAR_BFV(UDF_INIT *, UDF_ARGS *args, char *is_null,
                                  char *err) {
  try {
    std::string ct_str(args->args[0], args->lengths[0]);
    auto ctx = makeBfvContext();
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

// ------------------- SCALAR MULTIPLY -------------------

bool HERMES_MUL_SCALAR_BFV_init(UDF_INIT *initid, UDF_ARGS *args, char *msg) {
  if (args->arg_count != 2 || args->arg_type[0] != STRING_RESULT) {
    std::strcpy(
        msg, "HERMES_MUL_SCALAR_BFV(ciphertext, scalar) expects (string, int)");
    return 1;
  }
  initid->maybe_null = 1;
  initid->max_length = 65535;
  return 0;
}

char *HERMES_MUL_SCALAR_BFV(UDF_INIT *, UDF_ARGS *args, char *,
                            unsigned long *length, char *is_null, char *error) {
  try {
    auto ctx = makeBfvContext();
    std::string ct_str(args->args[0], args->lengths[0]);
    Ciphertext<DCRTPoly> ct = deserializeCiphertext(decodeBase64(ct_str));
    int64_t scalar = std::stoll(std::string(args->args[1], args->lengths[1]));
    auto pt = ctx->MakePackedPlaintext({scalar});
    pt->SetLength(1);
    auto ct_res = ctx->EvalMult(ct, pt);
    std::string encoded = encodeBase64(serializeCiphertext(ct_res));
    *length = encoded.size();
    return strdup(encoded.c_str());
  } catch (...) {
    *is_null = 1;
    *error = 1;
    return nullptr;
  }
}

// ------------------- CIPHERTEXT MULTIPLY -------------------

bool HERMES_MUL_BFV_init(UDF_INIT *initid, UDF_ARGS *args, char *msg) {
  if (args->arg_count != 2 || args->arg_type[0] != STRING_RESULT ||
      args->arg_type[1] != STRING_RESULT) {
    std::strcpy(msg, "HERMES_MUL_BFV requires two base64-encoded ciphertexts.");
    return 1;
  }
  initid->maybe_null = 1;
  initid->max_length = 65535;
  return 0;
}

char *HERMES_MUL_BFV(UDF_INIT *, UDF_ARGS *args, char *, unsigned long *len,
                     char *is_null, char *error) {
  try {
    auto ctx = makeBfvContext();
    std::string ct1_str(args->args[0], args->lengths[0]);
    std::string ct2_str(args->args[1], args->lengths[1]);
    auto ct1 = deserializeCiphertext(decodeBase64(ct1_str));
    auto ct2 = deserializeCiphertext(decodeBase64(ct2_str));
    auto result = ctx->EvalMult(ct1, ct2);
    std::string encoded = encodeBase64(serializeCiphertext(result));
    *len = encoded.size();
    return strdup(encoded.c_str());
  } catch (...) {
    *is_null = 1;
    *error = 1;
    return nullptr;
  }
}

// ------------------- SUM (Aggregate) -------------------

struct HermesSumContext {
  Ciphertext<DCRTPoly> acc;
  bool initialized = false;
};

bool HERMES_SUM_BFV_init(UDF_INIT *initid, UDF_ARGS *args, char *msg) {
  if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
    std::strcpy(msg, "HERMES_SUM_BFV expects one base64-encoded ciphertext.");
    return 1;
  }
  initid->ptr = reinterpret_cast<char *>(new HermesSumContext());
  initid->maybe_null = 1;
  return 0;
}

bool HERMES_SUM_BFV_add(UDF_INIT *initid, UDF_ARGS *args, char *is_null,
                        char *err) {
  try {
    auto ctx = makeBfvContext();
    HermesSumContext *sumctx =
        reinterpret_cast<HermesSumContext *>(initid->ptr);
    std::string ct_str(args->args[0], args->lengths[0]);
    auto ct = deserializeCiphertext(decodeBase64(ct_str));
    if (!sumctx->initialized) {
      sumctx->acc = ct;
      sumctx->initialized = true;
    } else {
      sumctx->acc = ctx->EvalAdd(sumctx->acc, ct);
    }
    return 0;
  } catch (...) {
    *is_null = 1;
    *err = 1;
    return 1;
  }
}

long long HERMES_SUM_BFV(UDF_INIT *initid, UDF_ARGS *, char *is_null,
                         char *err) {
  try {
    HermesSumContext *sumctx =
        reinterpret_cast<HermesSumContext *>(initid->ptr);
    if (!sumctx->initialized) {
      *is_null = 1;
      return 0;
    }
    auto ctx = makeBfvContext();
    auto sk = loadSecretKey();
    Plaintext pt;
    ctx->Decrypt(sk, sumctx->acc, &pt);
    pt->SetLength(1);
    auto v = pt->GetPackedValue();
    return v.empty() ? 0 : v[0];
  } catch (...) {
    *is_null = 1;
    *err = 1;
    return 0;
  }
}

void HERMES_SUM_BFV_clear(UDF_INIT *initid, char *, char *) {
  auto *ctx = reinterpret_cast<HermesSumContext *>(initid->ptr);
  ctx->initialized = false;
}
bool HERMES_SUM_BFV_reset(UDF_INIT *initid, UDF_ARGS *args, char *n, char *e) {
  HERMES_SUM_BFV_clear(initid, n, e);
  return HERMES_SUM_BFV_add(initid, args, n, e);
}
void HERMES_SUM_BFV_deinit(UDF_INIT *initid) {
  delete reinterpret_cast<HermesSumContext *>(initid->ptr);
}

} // extern "C"