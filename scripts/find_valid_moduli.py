#!/usr/bin/env python3
# find_valid_moduli.py — search primes p such that (p-1) % m == 0

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