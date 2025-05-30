/*
 * HERMES MySQL UDF Plugin
 * ------------------------------------------------------------
 * This file defines a set of MySQL User-Defined Functions (UDFs)
 * that enable encrypted SQL computation using OpenFHE (BFV scheme).
 *
 * Core Capabilities:
 * - Encryption/Decryption of single integers
 * - Homomorphic summation (aggregate)
 * - Homomorphic ciphertext-ciphertext multiplication
 * - Homomorphic scalar multiplication with plaintext values
 *
 * Exposed Functions:
 * - HERMES_ENC_SINGULAR_BFV(int) → base64 ciphertext
 *     Encrypts a single integer as a BFV ciphertext.
 *
 * - HERMES_DEC_SINGULAR_BFV(base64_ct) → int
 *     Decrypts a BFV ciphertext back to its original integer.
 *
 * - HERMES_SUM_BFV(base64_ct) → int
 *     Aggregate function: sums ciphertexts over SQL groups.
 *     Use with GROUP BY for encrypted aggregation.
 *
 * - HERMES_MUL_BFV(base64_ct1, base64_ct2) → base64 ciphertext
 *     Multiplies two ciphertexts homomorphically.
 *
 * - HERMES_MUL_SCALAR_BFV(base64_ct, scalar) → base64 ciphertext
 *     Performs plaintext-ciphertext scalar multiplication.
 *     The scalar can be int, double, or string-parsable integer.
 *
 * Technical Notes:
 * - All ciphertexts are serialized with OpenFHE’s binary format,
 *   and encoded/decoded using manual base64 routines.
 * - Keys and encryption context are globally shared via static
 *   singletons. This avoids repeated keygen but limits tenancy.
 * - Only single-slot ciphertexts are supported; no batching.
 * - Ciphertext size is bounded by max_length = 65535 bytes.
 *
 * Limitations:
 * - No support for vector packing or multi-slot encoding.
 * - Not thread-safe or multi-user safe (no key isolation).
 * - Does not persist keys across MySQL restarts.
 *
 * Author: Dr. Dongfang Zhao
 * Institution: University of Washington (HPDIC Lab)
 * Last Updated: May 26, 2025
 */

#include <cstring>
#include <iostream>
#include <mysql.h>
#include <sstream>
#include <string>
#include <vector>

#include "openfhe.h"
#include "base64.hpp"

using hermes::crypto::decodeBase64;
using hermes::crypto::encodeBase64;

using namespace lbcrypto;

struct HermesSumContext {
  Ciphertext<DCRTPoly> acc;
  bool initialized = false;
};

CryptoContext<DCRTPoly> &get_context() {
  static CryptoContext<DCRTPoly> ctx = [] {
    CCParams<CryptoContextBFVRNS> p;

    /**
     * ======================= Plaintext Modulus Notes ========================
     *
     * OpenFHE's BFV scheme uses a cyclotomic polynomial ring of order m,
     * where m is typically a power of 2. If not explicitly set, OpenFHE
     * defaults to:
     *
     *     m = 2^14 = 16384
     *
     * To ensure encoding succeeds, the plaintext modulus p must satisfy:
     *
     *     (p - 1) % m == 0     i.e.,   p ≡ 1 mod m
     *
     * If this condition is not met, OpenFHE will throw runtime exceptions:
     *
     *     SetParams_2n(): The modulus value must be prime.
     *     RootOfUnity(): The modulus and ring dimension must be compatible.
     *
     * The value 268,369,921 is a safe prime satisfying:
     *
     *     268,369,921 ≡ 1 mod 16384
     *
     * This supports signed plaintext integers up to approximately ±134 million.
     *
     * ⚠️  If you change the ring dimension m, you must select a new p such
     *     that p ≡ 1 mod m.
     */
    p.SetPlaintextModulus(268369921); // safe default for m = 16384

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

bool HERMES_MUL_SCALAR_BFV_init(UDF_INIT *initid, UDF_ARGS *args, char *msg) {
  if (args->arg_count != 2 || args->arg_type[0] != STRING_RESULT) {
    std::strcpy(msg, "HERMES_MUL_SCALAR_BFV(ciphertext, scalar) expects "
                     "(base64 string, scalar)");
    return 1;
  }

  if (args->arg_type[1] != INT_RESULT && args->arg_type[1] != STRING_RESULT &&
      args->arg_type[1] != REAL_RESULT) {
    std::strcpy(msg, "Second argument must be INT, STRING, or DOUBLE");
    return 1;
  }

  initid->maybe_null = 1;
  initid->max_length = 65535;
  return 0;
}

char *HERMES_MUL_SCALAR_BFV(UDF_INIT *, UDF_ARGS *args, char *,
                            unsigned long *length, char *is_null, char *error) {
  try {
    if (!args->args[0] || !args->args[1]) {
      *is_null = 1;
      return nullptr;
    }

    // Deserialize ciphertext
    std::string encoded(args->args[0], args->lengths[0]);
    std::string decoded = decodeBase64(encoded);
    std::stringstream ss(decoded);
    Ciphertext<DCRTPoly> ct;
    Serial::Deserialize(ct, ss, SerType::BINARY);

    // Parse scalar
    int64_t scalar = 0;
    if (args->arg_type[1] == INT_RESULT) {
      scalar = *reinterpret_cast<long long *>(args->args[1]);
    } else if (args->arg_type[1] == REAL_RESULT) {
      scalar = static_cast<int64_t>(*reinterpret_cast<double *>(args->args[1]));
    } else {
      std::string scalar_str(args->args[1], args->lengths[1]);
      scalar = std::stoll(scalar_str);
    }

    // Construct scalar plaintext and multiply
    Plaintext ptScalar = get_context()->MakePackedPlaintext({scalar});
    auto result = get_context()->EvalMult(ct, ptScalar);

    // Serialize result
    std::stringstream out;
    Serial::Serialize(result, out, SerType::BINARY);
    std::string reencoded = encodeBase64(out.str());

    char *ret = new char[reencoded.size() + 1];
    std::memcpy(ret, reencoded.data(), reencoded.size());
    ret[reencoded.size()] = '\0';

    *length = reencoded.size();
    *is_null = 0;
    *error = 0;
    return ret;

  } catch (const std::exception &e) {
    std::cerr << "[HERMES_MUL_SCALAR_BFV] exception: " << e.what() << std::endl;
    *is_null = 1;
    *error = 1;
    return nullptr;
  } catch (...) {
    std::cerr << "[HERMES_MUL_SCALAR_BFV] unknown exception" << std::endl;
    *is_null = 1;
    *error = 1;
    return nullptr;
  }
}

void HERMES_MUL_SCALAR_BFV_deinit(UDF_INIT *) {
  // No cleanup needed
}

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
    if (!args->args[0] || !args->args[1]) {
      *is_null = 1;
      return nullptr;
    }

    // Deserialize both ciphertexts
    std::string a_str(args->args[0], args->lengths[0]);
    std::string b_str(args->args[1], args->lengths[1]);
    std::stringstream sa(decodeBase64(a_str)), sb(decodeBase64(b_str));
    Ciphertext<DCRTPoly> ca, cb;
    Serial::Deserialize(ca, sa, SerType::BINARY);
    Serial::Deserialize(cb, sb, SerType::BINARY);

    // Perform EvalMult
    auto ctxt_mul = get_context()->EvalMult(ca, cb);

    // Re-encode and return
    std::stringstream sout;
    Serial::Serialize(ctxt_mul, sout, SerType::BINARY);
    std::string encoded = encodeBase64(sout.str());

    *len = encoded.size();
    *is_null = 0;
    *error = 0;
    return strdup(encoded.c_str());
  } catch (...) {
    *is_null = 1;
    *error = 1;
    return nullptr;
  }
}

void HERMES_MUL_BFV_deinit(UDF_INIT *) {}  

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