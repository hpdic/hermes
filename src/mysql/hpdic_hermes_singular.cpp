/*
 * HERMES MySQL UDF Plugin
 * ------------------------------------------------------------
 * This file defines a set of MySQL User-Defined Functions (UDFs)
 * that enable encrypted SQL computation using OpenFHE (BFV scheme).
 *
 * Core Functions:
 * - HERMES_ENC_SINGULAR_BFV: Encrypt a single integer value into a
 * base64-encoded ciphertext.
 * - HERMES_DEC_SINGULAR_BFV: Decrypt a base64 ciphertext into the original
 * integer.
 * - HERMES_SUM_BFV: SQL-compliant AGGREGATE FUNCTION for homomorphic summation
 * over ciphertexts.
 *
 * Technical Highlights:
 * - All ciphertexts are encoded and decoded via OpenFHE’s binary serializer +
 * manual base64.
 * - Context and keys are managed via static singletons for lazy initialization.
 * - Fully compatible with GROUP BY and native SQL aggregation pipelines.
 *
 * Limitations:
 * - Supports only single-slot BFV ciphertexts (no batching).
 * - Global key/context shared across all threads (not multi-tenant safe).
 * - No key rotation or key separation; not secure in adversarial settings.
 *
 * Author: Dr. Dongfang Zhao
 * Institution: University of Washington (HPDIC Lab)
 * Last Updated: May 26, 2025
 */

#include "openfhe.h"
#include <cstring>
#include <iostream>
#include <mysql.h>
#include <sstream>
#include <string>
#include <vector>

using namespace lbcrypto;

struct HermesSumContext {
  Ciphertext<DCRTPoly> acc;
  bool initialized = false;
};

static const std::string b64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string decodeBase64(const std::string &in) {
  std::vector<int> T(256, -1);
  for (int i = 0; i < 64; i++)
    T[b64_chars[i]] = i;
  std::string out;
  int val = 0, valb = -8;
  for (uint8_t c : in) {
    if (T[c] == -1)
      break;
    val = (val << 6) + T[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(char((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

static std::string encodeBase64(const std::string &in) {
  std::string out;
  int val = 0, valb = -6;
  for (uint8_t c : in) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(b64_chars[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6)
    out.push_back(b64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
  while (out.size() % 4)
    out.push_back('=');
  return out;
}

CryptoContext<DCRTPoly> &get_context() {
  static CryptoContext<DCRTPoly> ctx = [] {
    CCParams<CryptoContextBFVRNS> p;
    p.SetPlaintextModulus(65537);
    p.SetMultiplicativeDepth(2);
    auto c = GenCryptoContext(p);
    c->Enable(PKE);
    c->Enable(LEVELEDSHE);
    c->Enable(ADVANCEDSHE);
    return c;
  }();
  return ctx;
}

KeyPair<DCRTPoly> &get_keypair() {
  static KeyPair<DCRTPoly> kp = [] {
    auto &ctx = get_context();
    auto k = ctx->KeyGen();
    ctx->EvalMultKeyGen(k.secretKey);
    ctx->EvalSumKeyGen(k.secretKey);
    return k;
  }();
  return kp;
}

extern "C" {

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
    if (!args->args[0])
      return 0;
    std::string bin(args->args[0], args->lengths[0]);
    std::string decoded = decodeBase64(bin);
    std::stringstream ss(decoded);
    Ciphertext<DCRTPoly> ct;
    Serial::Deserialize(ct, ss, SerType::BINARY);
    auto *ctx = reinterpret_cast<HermesSumContext *>(initid->ptr);
    ctx->acc = ctx->initialized ? get_context()->EvalAdd(ctx->acc, ct) : ct;
    ctx->initialized = true;
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
    auto *ctx = reinterpret_cast<HermesSumContext *>(initid->ptr);
    if (!ctx->initialized) {
      *is_null = 1;
      return 0;
    }
    Plaintext pt;
    get_context()->Decrypt(get_keypair().secretKey, ctx->acc, &pt);
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
  reinterpret_cast<HermesSumContext *>(initid->ptr)->initialized = false;
}
bool HERMES_SUM_BFV_reset(UDF_INIT *initid, UDF_ARGS *args, char *n, char *e) {
  HERMES_SUM_BFV_clear(initid, n, e);
  return HERMES_SUM_BFV_add(initid, args, n, e);
}
void HERMES_SUM_BFV_deinit(UDF_INIT *initid) {
  delete reinterpret_cast<HermesSumContext *>(initid->ptr);
}

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
    if (!args->args[0]) {
      *is_null = 1;
      return 0;
    }
    std::string bin(args->args[0], args->lengths[0]);
    std::string decoded = decodeBase64(bin);
    std::stringstream ss(decoded);
    Ciphertext<DCRTPoly> ct;
    Serial::Deserialize(ct, ss, SerType::BINARY);
    Plaintext pt;
    get_context()->Decrypt(get_keypair().secretKey, ct, &pt);
    pt->SetLength(1);
    auto v = pt->GetPackedValue();
    return v.empty() ? 0 : v[0];
  } catch (...) {
    *is_null = 1;
    *err = 1;
    return 0;
  }
}

void HERMES_DEC_SINGULAR_BFV_deinit(UDF_INIT *) {}

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
    if (!args->args[0]) {
      *is_null = 1;
      return nullptr;
    }
    int64_t val = *reinterpret_cast<long long *>(args->args[0]);
    auto pt = get_context()->MakePackedPlaintext({val});
    pt->SetLength(1);
    auto ct = get_context()->Encrypt(get_keypair().publicKey, pt);
    std::stringstream ss;
    Serial::Serialize(ct, ss, SerType::BINARY);
    std::string encoded = encodeBase64(ss.str());
    *len = encoded.size();
    *is_null = 0;
    *err = 0;
    return strdup(encoded.c_str());
  } catch (...) {
    *is_null = 1;
    *err = 1;
    return nullptr;
  }
}

void HERMES_ENC_SINGULAR_BFV_deinit(UDF_INIT *) {}

} // extern "C"