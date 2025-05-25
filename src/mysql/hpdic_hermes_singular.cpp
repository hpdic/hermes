#include "openfhe.h"
#include <cstring>
#include <iostream>
#include <mysql.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace lbcrypto;

// ========== 聚合上下文结构 ==========
struct HermesSumContext {
  Ciphertext<DCRTPoly> acc;
  bool initialized;
};

// ========== Base64 编解码 ==========
static std::string decodeBase64(const std::string &in) {
  static const std::string b64_chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  std::vector<int> T(256, -1);
  for (int i = 0; i < 64; i++)
    T[b64_chars[i]] = i;
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

static std::string encodeBase64(const std::string &input) {
  static const char *base64_chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  int val = 0, valb = -6;
  for (uint8_t c : input) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(base64_chars[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6)
    out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
  while (out.size() % 4)
    out.push_back('=');
  return out;
}

// ========== 全局上下文 ==========
CryptoContext<DCRTPoly> g_context;
KeyPair<DCRTPoly> g_kp;
bool g_context_initialized = false;

void InitBFVContext() {
  if (g_context_initialized)
    return;

  std::cerr << "[HERMES] Initializing BFV context..." << std::endl;

  CCParams<CryptoContextBFVRNS> params;
  params.SetPlaintextModulus(65537);
  params.SetMultiplicativeDepth(2);

  g_context = GenCryptoContext(params);
  g_context->Enable(PKE);
  g_context->Enable(LEVELEDSHE);
  g_context->Enable(ADVANCEDSHE);

  g_kp = g_context->KeyGen();
  g_context->EvalMultKeyGen(g_kp.secretKey);
  g_context->EvalSumKeyGen(g_kp.secretKey);

  g_context_initialized = true;
  std::cerr << "[HERMES] BFV context and keys initialized" << std::endl;
}

extern "C" {

// ========== SUM INIT ==========
bool HERMES_SUM_BFV_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
    std::strcpy(message,
                "HERMES_SUM_BFV expects one base64-encoded ciphertext string.");
    return 1;
  }
  auto *ctx = new HermesSumContext();
  ctx->initialized = false;
  initid->ptr = reinterpret_cast<char *>(ctx);
  initid->maybe_null = 1;
  return 0;
}

// ========== SUM ADD ==========
bool HERMES_SUM_BFV_add(UDF_INIT *initid, UDF_ARGS *args, char *is_null,
                        char *error) {
  try {
    InitBFVContext();
    if (!args->args[0])
      return 0;

    std::string encoded(args->args[0], args->lengths[0]);
    std::string bin = decodeBase64(encoded);
    std::stringstream ss(bin);

    Ciphertext<DCRTPoly> ct;
    Serial::Deserialize(ct, ss, SerType::BINARY);

    auto *ctx = reinterpret_cast<HermesSumContext *>(initid->ptr);
    if (!ctx->initialized) {
      ctx->acc = ct;
      ctx->initialized = true;
    } else {
      ctx->acc = g_context->EvalAdd(ctx->acc, ct);
    }
    return 0;
  } catch (...) {
    *is_null = 1;
    *error = 1;
    return 1;
  }
}

// ========== SUM FUNC ==========
long long HERMES_SUM_BFV(UDF_INIT *initid, UDF_ARGS *, char *is_null,
                         char *error) {
  try {
    InitBFVContext();
    auto *ctx = reinterpret_cast<HermesSumContext *>(initid->ptr);
    if (!ctx->initialized) {
      *is_null = 1;
      return 0;
    }
    Plaintext pt;
    g_context->Decrypt(g_kp.secretKey, ctx->acc, &pt);
    pt->SetLength(1);
    auto packed = pt->GetPackedValue();
    return static_cast<long long>(packed.empty() ? 0 : packed[0]);
  } catch (...) {
    *is_null = 1;
    *error = 1;
    return 0;
  }
}

// ========== SUM CLEANUP ==========
void HERMES_SUM_BFV_clear(UDF_INIT *initid, char *, char *) {
  auto *ctx = reinterpret_cast<HermesSumContext *>(initid->ptr);
  ctx->initialized = false;
}

bool HERMES_SUM_BFV_reset(UDF_INIT *initid, UDF_ARGS *args, char *is_null,
                          char *error) {
  HERMES_SUM_BFV_clear(initid, is_null, error);
  return HERMES_SUM_BFV_add(initid, args, is_null, error);
}

void HERMES_SUM_BFV_deinit(UDF_INIT *initid) {
  delete reinterpret_cast<HermesSumContext *>(initid->ptr);
}

// ========== DECRYPT ==========
bool HERMES_DEC_SINGULAR_BFV_init(UDF_INIT *initid, UDF_ARGS *args,
                                  char *message) {
  if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
    std::strcpy(message,
                "HERMES_DEC_SINGULAR_BFV requires 1 base64 string argument.");
    return 1;
  }
  initid->maybe_null = 1;
  return 0;
}

long long HERMES_DEC_SINGULAR_BFV(UDF_INIT *, UDF_ARGS *args, char *is_null,
                                  char *error) {
  try {
    InitBFVContext();
    if (!args->args[0]) {
      *is_null = 1;
      return 0;
    }

    std::string encoded(args->args[0], args->lengths[0]);
    std::string decoded = decodeBase64(encoded);
    std::stringstream ss(decoded);

    Ciphertext<DCRTPoly> ct;
    Serial::Deserialize(ct, ss, SerType::BINARY);

    Plaintext pt;
    g_context->Decrypt(g_kp.secretKey, ct, &pt);
    pt->SetLength(1);
    auto packed = pt->GetPackedValue();
    return static_cast<long long>(packed.empty() ? 0 : packed[0]);
  } catch (...) {
    *is_null = 1;
    *error = 1;
    return 0;
  }
}

void HERMES_DEC_SINGULAR_BFV_deinit(UDF_INIT *) {}

// ========== ENCRYPT ==========
bool HERMES_ENC_SINGULAR_BFV_init(UDF_INIT *initid, UDF_ARGS *args,
                                  char *message) {
  if (args->arg_count != 1 || args->arg_type[0] != INT_RESULT) {
    std::strcpy(message,
                "HERMES_ENC_SINGULAR_BFV requires 1 integer argument.");
    return 1;
  }
  initid->maybe_null = 1;
  initid->max_length = 65535;
  return 0;
}

char *HERMES_ENC_SINGULAR_BFV(UDF_INIT *, UDF_ARGS *args, char *,
                              unsigned long *length, char *is_null,
                              char *error) {
  try {
    InitBFVContext();

    if (!args->args[0]) {
      *is_null = 1;
      return nullptr;
    }

    int64_t val = *reinterpret_cast<long long *>(args->args[0]);
    Plaintext pt = g_context->MakePackedPlaintext({val});
    pt->SetLength(1);

    auto ct = g_context->Encrypt(g_kp.publicKey, pt);
    std::stringstream ss;
    Serial::Serialize(ct, ss, SerType::BINARY);
    std::string encoded = encodeBase64(ss.str());

    char *output = strdup(encoded.c_str());
    *length = encoded.size();
    *is_null = 0;
    *error = 0;
    return output;
  } catch (...) {
    *is_null = 1;
    *error = 1;
    return nullptr;
  }
}

void HERMES_ENC_SINGULAR_BFV_deinit(UDF_INIT *) {}

} // extern "C"