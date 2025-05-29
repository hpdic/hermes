#!/bin/bash
# run_crypto.sh — Run C++ unit tests for crypto module
# Author: Dr. Dongfang Zhao (dzhao@cs.washington.edu)
# Last Updated: 2025-05-28
#
# Usage: ./run_crypto.sh
# This script runs the standalone test executables for keygen, encryption, and decryption.

set -e

echo "[*] Running crypto module unit tests..."

BIN_DIR="./build/src/crypto"  # Or wherever CMake puts test binaries

for exe in test_keygen test_encrypt test_decrypt test_eval test_serialize; do
  if [[ -f "$BIN_DIR/$exe" ]]; then
    echo -e "\n[+] Running $exe..."
    "$BIN_DIR/$exe"
  else
    echo "[!] Binary $exe not found in $BIN_DIR"
    exit 1
  fi
done

echo -e "\n[✓] All crypto unit tests passed."