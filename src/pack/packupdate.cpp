/*
 * File: src/pack/packupdate.cpp
 * ------------------------------------------------------------
 * HERMES Update UDFs for Packed Ciphertexts (Preliminary Version)
 *
 * This file defines two MySQL UDFs for updating homomorphically encrypted
 * vectors stored in a packed ciphertext:
 *
 *   1. HERMES_PACK_ADD(ciphertext_base64, val, index)
 *      - Inserts `val` at a specified `index` slot via EvalAdd with a
 *        one-hot encrypted plaintext.
 *
 *   2. HERMES_PACK_RMV(ciphertext_base64, index, k)
 *      - Removes the value at a specified `index` slot by:
 *        (i) zeroing that slot with a plaintext mask,
 *        (ii) copying the last occupied slot (at `k - 1`) to fill the gap,
 *        (iii) clearing the original tail slot.
 *      - This behavior ensures the ciphertext remains compact (no gaps).
 *
 * This version compiles and runs under OpenFHE v1.2.4 with BFV scheme.
 *
 * CURRENT DESIGN ASSUMPTIONS AND LIMITATIONS:
 * ------------------------------------------------------------
 *  ❶ No tracking of tuple-to-slot assignment:
 *     - There is no maintained mapping between plaintext tuple IDs and
 *       encrypted slot positions. It is assumed that GROUP BY tuples
 *       are encoded into packed ciphertexts in sequential order.
 *
 *  ❷ No automatic slot occupation state management:
 *     - The caller must supply the number of valid slots `k` explicitly.
 *     - `HERMES_PACK_ADD` does not manage free slot allocation;
 *       it inserts at the given index directly.
 *
 *  ❸ No local sum tracking:
 *     - The ciphertext does not internally maintain the sum of plaintext values
 *       (i.e., "local sum") or slot occupancy metadata.
 *     - Reserved slots like slot[0] (for count) and slot[n−1] (for sum) are not
 * updated.
 *
 * IMPLEMENTED EXTENSIONS:
 * ------------------------------------------------------------
 *  ✅ Deletion with compaction:
 *     - The `HERMES_PACK_RMV` function performs in-place compaction by moving
 * the last valid slot into the position of the removed slot, then zeroing out
 * the tail.
 *     - This avoids internal fragmentation in packed ciphertexts.
 *
 * FUTURE EXTENSIONS (Planned Work):
 * ------------------------------------------------------------
 *  1. Add tuple-to-slot mapping:
 *     - Extend the plaintext database with a column recording each tuple’s
 *       assigned slot index within the group ciphertext.
 *
 *  2. Automate slot occupation tracking:
 *     - Track and maintain the number of valid slots (e.g., via metadata or
 * separate table).
 *     - Automatically assign next free slot on insertion and adjust on
 * deletion.
 *
 *  3. Maintain local sum as metadata:
 *     - Encode local slot count and cumulative sum directly into reserved
 * slots.
 *     - Update these during each add/rmv operation.
 *
 *  4. Optimize removal without EvalMult:
 *     - Current deletion uses ciphertext × plaintext masks (EvalMult),
 *       which increases noise and may require bootstrapping.
 *     - Future versions will explore rotation-based overwrites
 *       to eliminate EvalMult and reduce noise growth.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: June 1st, 2025
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

    std::memcpy(result, out.data(), out.size());
    *length = out.size();
    return result;
  } catch (...) {
    *is_null = 1;
    *err = 1;
    return nullptr;
  }
}

// UDF: HERMES_PACK_RMV(ciphertext, index)
bool HERMES_PACK_RMV_init(UDF_INIT *, UDF_ARGS *args, char *msg) {
  if (args->arg_count != 2 || args->arg_type[0] != STRING_RESULT ||
      args->arg_type[1] != INT_RESULT) {
    std::strcpy(msg, "HERMES_PACK_RMV expects (string, int)");
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
    int64_t k = *reinterpret_cast<long long *>(
        args->args[2]); // current used slot count

    auto ct = deserializeCiphertext(decodeBase64(ct_str));
    size_t slot_count = cc->GetEncodingParams()->GetBatchSize();

    if (index < 0 || index >= k || k > static_cast<int64_t>(slot_count)) {
      *is_null = 1;
      *err = 1;
      return nullptr;
    }

    // If removing the last slot, just mask it out
    if (index == k - 1) {
      std::vector<int64_t> mask(slot_count, 1);
      mask[index] = 0;
      auto pt_mask = cc->MakePackedPlaintext(mask);
      pt_mask->SetLength(slot_count);
      auto ct_masked = cc->EvalMult(ct, pt_mask);
      auto out = encodeBase64(serializeCiphertext(ct_masked));
      std::memcpy(result, out.data(), out.size());
      *length = out.size();
      return result;
    }

    // Step 1: Clear slot[index]
    std::vector<int64_t> mask(slot_count, 1);
    mask[index] = 0;
    auto pt_mask = cc->MakePackedPlaintext(mask);
    pt_mask->SetLength(slot_count);
    auto ct_cleared = cc->EvalMult(ct, pt_mask);

    // Step 2: Extract value at slot[k-1]
    std::vector<int64_t> last_mask(slot_count, 0);
    last_mask[k - 1] = 1;
    auto pt_last = cc->MakePackedPlaintext(last_mask);
    pt_last->SetLength(slot_count);
    auto ct_last_val = cc->EvalMult(ct, pt_last);

    // Step 3: Rotate last_val to index position
    auto ct_shifted =
        cc->EvalAtIndex(ct_last_val, index - (k - 1)); // right rotation

    // Step 4: Add it into cleared ct
    auto ct_updated = cc->EvalAdd(ct_cleared, ct_shifted);

    // Step 5: Zero out slot[k-1] (optional)
    std::vector<int64_t> final_mask(slot_count, 1);
    final_mask[k - 1] = 0;
    auto pt_final_mask = cc->MakePackedPlaintext(final_mask);
    pt_final_mask->SetLength(slot_count);
    auto ct_final = cc->EvalMult(ct_updated, pt_final_mask);

    // Output
    auto out = encodeBase64(serializeCiphertext(ct_final));
    std::memcpy(result, out.data(), out.size());
    *length = out.size();
    return result;

  } catch (...) {
    *is_null = 1;
    *err = 1;
    return nullptr;
  }
}

} // extern "C"