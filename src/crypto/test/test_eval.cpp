/*
 * File: test_eval.cpp
 * HERMES FHE Unit Test
 * ------------------------------------------------------------
 * This test verifies basic homomorphic evaluation operations
 * in the BFV scheme, including EvalAdd, EvalMult, EvalAddConst,
 * and EvalMultConst.
 *
 * Author: Dongfang Zhao (dzhao@cs.washington.edu)
 * Institution: University of Washington
 * Last Updated: May 29, 2025
 */

#include "context.hpp"
#include "decrypt.hpp"
#include "encrypt.hpp"
#include "keygen.hpp"
#include "openfhe.h"
#include <cassert>
#include <iostream>

using namespace hermes::crypto;
using namespace lbcrypto;

int main() {
  std::cout << "[test_eval] Initializing BFV context..." << std::endl;
  auto ctx = makeBfvContext();
  auto kp = generateKeypair(ctx);

  int64_t a = 7;
  int64_t b = 5;
  int64_t c = 3;
  int64_t d = 4;

  std::cout << "[test_eval] Encrypting a = " << a << ", b = " << b << std::endl;

  Plaintext pt_a = ctx->MakePackedPlaintext({a});
  Plaintext pt_b = ctx->MakePackedPlaintext({b});

  auto ct_a = encrypt(ctx, kp.publicKey, pt_a);
  auto ct_b = encrypt(ctx, kp.publicKey, pt_b);

  // EvalAdd
  auto ct_add = ctx->EvalAdd(ct_a, ct_b);
  Plaintext pt_add;
  ctx->Decrypt(kp.secretKey, ct_add, &pt_add);
  pt_add->SetLength(1);
  std::cout << "[test_eval] a + b = " << pt_add->GetPackedValue()[0]
            << std::endl;
  assert(pt_add->GetPackedValue()[0] == a + b);

  // EvalMult
  auto ct_mul = ctx->EvalMult(ct_a, ct_b);
  Plaintext pt_mul;
  ctx->Decrypt(kp.secretKey, ct_mul, &pt_mul);
  pt_mul->SetLength(1);
  std::cout << "[test_eval] a * b = " << pt_mul->GetPackedValue()[0]
            << std::endl;
  assert(pt_mul->GetPackedValue()[0] == a * b);

  // EvalAddConst
  auto pt_c = ctx->MakePackedPlaintext({c});
  auto ct_add_const = ctx->EvalAdd(ct_a, pt_c);  
  Plaintext pt_add_const;
  ctx->Decrypt(kp.secretKey, ct_add_const, &pt_add_const);
  pt_add_const->SetLength(1);
  std::cout << "[test_eval] a + " << c << " = "
            << pt_add_const->GetPackedValue()[0] << std::endl;
  assert(pt_add_const->GetPackedValue()[0] == a + c);

  // EvalMultConst
  auto pt_const = ctx->MakePackedPlaintext({d});
  auto ct_mul_const = ctx->EvalMult(ct_b, pt_const);
  Plaintext pt_mul_const;
  ctx->Decrypt(kp.secretKey, ct_mul_const, &pt_mul_const);
  pt_mul_const->SetLength(1);
  std::cout << "[test_eval] b * " << d << " = "
            << pt_mul_const->GetPackedValue()[0] << std::endl;
  assert(pt_mul_const->GetPackedValue()[0] == b * d);

  std::cout << "[✓] All evaluation tests passed." << std::endl;
  return 0;
}