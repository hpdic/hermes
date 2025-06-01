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
 *   2. HERMES_PACK_RMV(ciphertext_base64, index)
 *      - Removes the value at a specified `index` slot by applying a
 *        multiplicative mask (1s except at index).
 *
 * This version compiles and runs under OpenFHE v1.2.4 with BFV scheme.
 *
 * CURRENT DESIGN ASSUMPTIONS AND LIMITATIONS:
 * ------------------------------------------------------------
 *  ❶ No tracking of slot assignment:
 *     - There is no maintained mapping between plaintext tuple IDs and
 *       encrypted slot positions. It is assumed that GROUP BY tuples
 *       are encoded into packed ciphertexts in sequential order.
 *
 *  ❷ No slot occupation state management:
 *     - The ciphertext does not record how many slots are currently valid,
 *       nor which intermediate slots have been removed.
 *     - `HERMES_PACK_RMV` leaves a zero in the slot but does not shift
 *       or reclaim that position.
 *
 *  ❸ No local sum maintenance:
 *     - The ciphertext does not maintain the sum of plaintext values
 *       (i.e., the "local sum") within the vector.
 *     - No adjustment is made to any metadata slots (e.g., first or last).
 *
 * FUTURE EXTENSIONS (Planned Work):
 * ------------------------------------------------------------
 *  1. Add tuple-to-slot mapping:
 *     - Add a new column to the original plaintext table to record the
 *       assigned slot index for each tuple in a group.
 *
 *  2. Track slot occupation and enforce packed semantics:
 *     - Upon insert, always place the value in the first available empty
 *       slot (e.g., the next unused index).
 *     - Upon removal, overwrite the deleted slot by rotating in the last
 *       occupied slot, then zeroing the tail.
 *     - Adjust slot occupation count accordingly.
 *
 *  3. Maintain local sum as metadata:
 *     - Store the slot count and local sum in reserved slots
 *       (e.g., slot[0] = size, slot[n-1] = sum).
 *     - Update this metadata during each add/rmv operation.
 *
 *  4. Avoid EvalMult masks if possible:
 *     - Current design uses homomorphic multiplication for slot nullification,
 *       which may increase noise budget significantly.
 *     - Future versions will explore Galois rotation-based rewrites to
 *       eliminate multiplication and reduce bootstrapping pressure.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 31, 2025
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

    auto ct = deserializeCiphertext(decodeBase64(ct_str));

    size_t slot_count = cc->GetEncodingParams()->GetBatchSize();
    std::vector<int64_t> mask(slot_count, 1);
    if (index < 0 || index >= static_cast<int64_t>(slot_count)) {
      *is_null = 1;
      *err = 1;
      return nullptr;
    }
    mask[index] = 0;
    auto pt_mask = cc->MakePackedPlaintext(mask);
    pt_mask->SetLength(slot_count);
    auto ct_masked = cc->EvalMult(ct, pt_mask);

    auto out = encodeBase64(serializeCiphertext(ct_masked));
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