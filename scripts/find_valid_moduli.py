#!/usr/bin/env python3
# ============================================================
# find_valid_moduli.py — Search for Valid Prime Moduli
# Author: Dr. Dongfang Zhao (dzhao@cs.washington.edu)
# Last Updated: 2025-05-26
#
# This script searches for prime integers p such that (p - 1) 
# is divisible by a given integer m; that is:
#
#     (p - 1) % m == 0
#
# These primes p ensure the existence of a multiplicative 
# subgroup of order m in the multiplicative group ℤ_p^×.
# This property is critical for many applications, including:
#
# - Constructing primitive m-th roots of unity in ℤ_p
# - Enabling Number Theoretic Transforms (NTT) of length m
# - Generating plaintext modulus p with known cyclotomic order
# - Supporting batching in homomorphic encryption schemes
#   (e.g., BFV, BGV, CKKS) via CRT packing over ℤ_p
#
# ----------------------------
# Usage:
#   python find_valid_moduli.py <m> [--limit N]
#
# Parameters:
#   <m>         — Desired subgroup order
#   --limit N   — (Optional) Upper bound on candidate primes to search
#                 Default is 10,000
#
# Output:
#   A printed list of primes p satisfying (p - 1) % m == 0,
#   along with their corresponding values of (p - 1) // m
#
# Example:
#   $ python find_valid_moduli.py 128 --limit 5000
#   Valid primes p such that (p - 1) % 128 == 0:
#   p = 257     (k = 2)
#   p = 641     (k = 5)
#   ...
#
# Note:
#   - The primes found can be directly used to define plaintext moduli
#     for OpenFHE’s packed encoding schemes.
# ============================================================

import argparse
from sympy import isprime

def find_valid_moduli(m, min_val, max_val):
    print(f"Valid BFV plaintext primes for ring dimension m = {m}:")
    for p in range(min_val, max_val):
        if isprime(p) and (p - 1) % m == 0:
            print(p)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Find valid BFV plaintext moduli for OpenFHE."
    )
    parser.add_argument("--ring-dim", type=int, default=16384,
                        help="Ring dimension (e.g., 16384)")
    parser.add_argument("--min", type=int, default=100_000_123,
                        help="Minimum modulus to consider")
    parser.add_argument("--max", type=int, default=300_000_000,
                        help="Maximum modulus to consider")
    args = parser.parse_args()

    find_valid_moduli(args.ring_dim, args.min, args.max)