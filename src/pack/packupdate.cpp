/*
 * File: src/pack/packupdate.cpp
 * ------------------------------------------------------------
 * HERMES Update UDFs for Packed Ciphertexts (Preliminary Version)
 *
 * This file defines three MySQL UDFs for updating homomorphically encrypted
 * vectors stored in a packed ciphertext:
 *
 *   1. HERMES_PACK_ADD(ciphertext_base64, val, index)
 *      - Inserts `val` at a specified `index` slot via EvalAdd with a
 *        one-hot encrypted plaintext.
 *
 *   2. HERMES_PACK_RMV(ciphertext_base64, index_to_remove, current_slot_count)
 *      - Removes the value at a specified `index` slot by:
 *        (i) zeroing that slot with a plaintext mask,
 *        (ii) copying the last occupied slot (at `k - 1`) to fill the gap,
 *        (iii) clearing the original tail slot.
 *      - This behavior ensures the ciphertext remains dense (no gaps).
 *
 *   3. HERMES_SUM_CIPHERS(cipher1_base64, cipher2_base64)
 *      - Performs homomorphic EvalAdd on two packed ciphertexts.
 *
 * This version compiles and runs under OpenFHE v1.2.4 with the BFV scheme.
 *
 * CURRENT DESIGN ASSUMPTIONS AND CAPABILITIES:
 * ------------------------------------------------------------
 *  ✅ Tuple-slot mapping is external:
 *     - The UDF does not track which tuple maps to which slot. Instead,
 *       we assume the database layer maintains this mapping (e.g., via
 *       a separate index column).
 *
 *  ✅ Slot occupancy is dense and maintained:
 *     - The UDFs maintain a compact ciphertext layout with no unused slots
 *       between values. Deletions compact the vector by overwriting the
 *       deleted slot and zeroing the tail.
 *
 * FUTURE EXTENSIONS (Planned Directions):
 * ------------------------------------------------------------
 *  1. Alternative to in-place compaction:
 *     The current deletion strategy performs in-place compaction by moving
 *     the last slot into the removed position. This simplifies slot tracking
 *     and avoids fragmentation, but incurs one Galois rotation and two
 *     homomorphic multiplications per operation.
 *
 *     Other strategies—such as marking slots as inactive or maintaining
 *     an external free-slot bitmap—may reduce cryptographic overhead,
 *     but require more complex database-side logic to manage occupancy state.
 *
 *     The current design makes a deliberate trade-off: moderate homomorphic
 *     cost in exchange for dense ciphertext layout and simpler slot management.
 *
 *  2. Maskless deletion via rotation:
 *     It is possible to implement removal purely using Galois rotations and
 *     additions—by cyclically rotating the tail value into the target position
 *     and subtracting out the original. This would avoid EvalMult altogether,
 *     but may require additional Galois keys and is unlikely to yield better
 *     performance in practice.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: June 1, 2025
 */

#include "context.hpp"
#include "keygen.hpp"
#include "base64.hpp"
#include "serialize.hpp"

#include <cstring>
#include <mysql/mysql.h>
#include <mysql/udf_registration_types.h>
#include <string>
#include <vector>

using namespace lbcrypto;
using namespace hermes::crypto;

std::string getPackedPrefix(const lbcrypto::Plaintext &pt, size_t n = 10) {
  const auto &vec = pt->GetPackedValue();
  std::ostringstream oss;
  oss << "[";
  for (size_t i = 0; i < std::min(n, vec.size()); ++i) {
    if (i > 0)
      oss << ", ";
    oss << vec[i];
  }
  oss << "]";
  return oss.str();
}

extern "C" {

// UDF: HERMES_PACK_ADD(ciphertext, val, index)
bool HERMES_PACK_ADD_init(UDF_INIT *, UDF_ARGS *args, char *msg) {
  if (args->arg_count != 3 || args->arg_type[0] != STRING_RESULT ||
      args->arg_type[1] != INT_RESULT || args->arg_type[2] != INT_RESULT) {
    std::strcpy(msg, "HERMES_PACK_ADD expects (string, int, int)");
    return true;
  }
  return false;
}

char *HERMES_PACK_ADD(UDF_INIT *, UDF_ARGS *args, char *result,
                      unsigned long *length, char *is_null, char *err) {
  try {
    auto cc = getGC();
    auto pk = loadPublicKey();

    std::string ct_str(args->args[0], args->lengths[0]);
    int64_t new_val = *reinterpret_cast<long long *>(args->args[1]);
    int64_t index = *reinterpret_cast<long long *>(args->args[2]);

    auto ct_old = deserializeCiphertext(decodeBase64(ct_str));

    size_t slot_count = cc->GetEncodingParams()->GetBatchSize();
    std::vector<int64_t> vec(slot_count, 0);
    if (index < 0 || index >= static_cast<int64_t>(slot_count)) {
      *is_null = 1;
      *err = 1;
      return nullptr;
    }
    vec[index] = new_val;
    auto pt_new = cc->MakePackedPlaintext(vec);
    pt_new->SetLength(slot_count);

    auto ct_new = cc->Encrypt(pk, pt_new);
    auto ct_updated = cc->EvalAdd(ct_old, ct_new);
    auto out = encodeBase64(serializeCiphertext(ct_updated));

    char *buf = static_cast<char *>(malloc(out.size()));
    std::memcpy(buf, out.data(), out.size());
    *length = out.size();
    return buf;
  } 
  catch (...) {
    *is_null = 1;
    *err = 1;
    return nullptr;
  }
}

void HERMES_PACK_ADD_deinit(UDF_INIT *initid) {
  if (initid->ptr) {
    free(initid->ptr);
    initid->ptr = nullptr;
  }
}

// UDF: HERMES_PACK_RMV(ciphertext_base64, index_to_remove, current_slot_count)
/**
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: 2025-06-01
 */
bool HERMES_PACK_RMV_init(UDF_INIT *initid, UDF_ARGS *args, char *msg) {
  initid->max_length = 65535;

  if (args->arg_count != 3 || args->arg_type[0] != STRING_RESULT ||
      args->arg_type[1] != INT_RESULT || args->arg_type[2] != INT_RESULT) {
    std::strcpy(msg, "HERMES_PACK_RMV expects (string, int, int)");
    return true;
  }
  return false;
}

char *HERMES_PACK_RMV(UDF_INIT *, UDF_ARGS *args, char *result,
                      unsigned long *length, char *is_null, char *err) {
  try {
    auto cc = getGC();

    std::string ct_str(args->args[0], args->lengths[0]);
    int64_t index = *reinterpret_cast<long long *>(args->args[1]);
    int64_t k = *reinterpret_cast<long long *>(args->args[2]);

    auto ct = deserializeCiphertext(decodeBase64(ct_str));
    size_t slot_count = cc->GetEncodingParams()->GetBatchSize();

    std::cerr << "[RMV] index = " << index << ", k = " << k
              << ", slot_count = " << slot_count << std::endl;

    if (index < 0 || index >= k || k > static_cast<int64_t>(slot_count)) {
      *is_null = 1;
      *err = 1;
      return nullptr;
    }

    auto secretKey = loadSecretKey();

    std::vector<int64_t> mask(slot_count, 1);
    mask[index] = 0;
    auto pt_mask = cc->MakePackedPlaintext(mask);
    pt_mask->SetLength(slot_count);

    if (index == k - 1) {
      auto ct_masked = cc->EvalMult(ct, pt_mask);

      Plaintext pt;
      cc->Decrypt(secretKey, ct_masked, &pt);
      pt->SetLength(slot_count);
      std::cerr << "[RMV] (tail case) after masking = " 
                << getPackedPrefix(pt)
                << std::endl;

      auto out_str = encodeBase64(serializeCiphertext(ct_masked));
      std::memcpy(result, out_str.data(), out_str.size());
      *length = out_str.size();
      return result;
    }

    // Step 1: clear index
    auto ct_cleared = cc->EvalMult(ct, pt_mask);
    Plaintext pt1;
    cc->Decrypt(secretKey, ct_cleared, &pt1);
    pt1->SetLength(slot_count);
    std::cerr << "[RMV] after clear[" << index
              << "] = " << getPackedPrefix(pt1) << std::endl;

    // Step 2: extract last slot
    std::vector<int64_t> last_mask(slot_count, 0);
    last_mask[k - 1] = 1;
    auto pt_last = cc->MakePackedPlaintext(last_mask);
    pt_last->SetLength(slot_count);
    auto ct_last_val = cc->EvalMult(ct, pt_last);
    Plaintext pt2;
    cc->Decrypt(secretKey, ct_last_val, &pt2);
    pt2->SetLength(slot_count);
    std::cerr << "[RMV] extracted last slot = " << getPackedPrefix(pt2)
              << std::endl;

    // Step 3: shift to index
    std::string keyTag = secretKey->GetKeyTag();
    auto galoisMap = cc->GetEvalAutomorphismKeyMap(keyTag);
    std::cerr << "[DEBUG] registered Galois keys = { ";
    for (auto &[idx, key] : galoisMap) {
      std::cerr << idx << " ";
    }
    std::cerr << "}" << std::endl;
    auto ct_shifted = cc->EvalAtIndex(ct_last_val, (k - 1) - index);
    Plaintext pt3;
    cc->Decrypt(secretKey, ct_shifted, &pt3);
    pt3->SetLength(slot_count);
    std::cerr << "[RMV] shifted last slot to [" << index
              << "] = " << getPackedPrefix(pt3) << std::endl;

    // Step 4: insert into cleared
    auto ct_updated = cc->EvalAdd(ct_cleared, ct_shifted);
    Plaintext pt4;
    cc->Decrypt(secretKey, ct_updated, &pt4);
    pt4->SetLength(slot_count);
    std::cerr << "[RMV] after insert = " << getPackedPrefix(pt4) << std::endl;

    // Step 5: clear k-1 tail
    std::vector<int64_t> final_mask(slot_count, 1);
    final_mask[k - 1] = 0;
    auto pt_final_mask = cc->MakePackedPlaintext(final_mask);
    pt_final_mask->SetLength(slot_count);
    auto ct_final = cc->EvalMult(ct_updated, pt_final_mask);
    Plaintext pt5;
    cc->Decrypt(secretKey, ct_final, &pt5);
    pt5->SetLength(slot_count);
    std::cerr << "[RMV] final ciphertext = " << getPackedPrefix(pt5)
              << std::endl;

    auto out_str = encodeBase64(serializeCiphertext(ct_final));
    std::cerr << "[RMV] final base64 length = " << out_str.size() << std::endl;

    char *buffer = static_cast<char *>(malloc(out_str.size()));
    if (!buffer) {
      std::cerr << "[RMV] malloc failed for output buffer." << std::endl;
      *is_null = 1;
      *err = 1;
      return nullptr;
    }
    std::memcpy(buffer, out_str.data(), out_str.size());
    *length = out_str.size();
    return buffer;
  } 
  catch (const std::exception &e) {
    std::cerr << "[RMV] std::exception caught: " << e.what() << std::endl;
    *is_null = 1;
    *err = 1;
    return nullptr;
  } catch (...) {
    std::cerr
        << "[RMV] Unknown exception caught during ciphertext removal logic."
        << std::endl;
    *is_null = 1;
    *err = 1;
    return nullptr;
  }
}

/*
 * HERMES_SUM_CIPHERS
 * ------------------------------------------------------------
 * Scalar UDF: Performs homomorphic addition of two BFV ciphertexts.
 *
 * INPUT:
 *   - Two base64-encoded ciphertext strings: (c1_base64, c2_base64)
 *     Each string represents a serialized OpenFHE ciphertext encrypted
 *     using the same context and public key.
 *
 * FUNCTIONALITY:
 *   - Deserialize both ciphertexts.
 *   - Compute EvalAdd(c1, c2) using OpenFHE BFV context.
 *   - Return a base64-encoded string of the resulting ciphertext.
 *
 * AUTHOR:
 *   Dongfang Zhao (dzhao@cs.washington.edu)
 *   University of Washington
 *   Last Updated: June 1, 2025
 */

bool HERMES_SUM_CIPHERS_init(UDF_INIT *initid, UDF_ARGS *args, char *msg) {
  if (args->arg_count != 2 || args->arg_type[0] != STRING_RESULT ||
      args->arg_type[1] != STRING_RESULT) {
    std::strcpy(msg, "HERMES_SUM_CIPHERS expects two base64-encoded strings.");
    return true;
  }
  initid->maybe_null = 1;
  initid->max_length = 65535;
  return false;
}

char *HERMES_SUM_CIPHERS(UDF_INIT *initid, UDF_ARGS *args, char *result,
                         unsigned long *length, char *is_null, char *error) {
  try {
    std::string s1(args->args[0], args->lengths[0]);
    std::string s2(args->args[1], args->lengths[1]);

    auto cc = getGC();
    auto ct1 = deserializeCiphertext(decodeBase64(s1));
    auto ct2 = deserializeCiphertext(decodeBase64(s2));
    auto ct_sum = cc->EvalAdd(ct1, ct2);

    std::string encoded = encodeBase64(serializeCiphertext(ct_sum));

    // ✅ Use heap allocation
    char *out = static_cast<char *>(malloc(encoded.size() + 1));
    if (!out) {
      *is_null = 1;
      *error = 1;
      return nullptr;
    }

    std::memcpy(out, encoded.data(), encoded.size());
    out[encoded.size()] = '\0';
    *length = encoded.size();
    initid->ptr = out; // track for deinit

    return out;
  } catch (...) {
    *is_null = 1;
    *error = 1;
    return nullptr;
  }
}

void HERMES_SUM_CIPHERS_deinit(UDF_INIT *initid) {
  if (initid->ptr) {
    free(initid->ptr);
    initid->ptr = nullptr;
  }
}

} // extern "C"