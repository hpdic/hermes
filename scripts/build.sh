#!/bin/bash
# ============================================================
# build.sh — Build and Register Hermes MySQL UDF Plugin
# Author: Dr. Dongfang Zhao (dzhao@cs.washington.edu)
# Last Updated: 2025-05-26
#
# This script compiles the Hermes plugin (based on OpenFHE),
# installs it to the MySQL plugin directory, restarts MySQL
# to clear previous UDF state, and registers the following
# homomorphic encryption functions as native SQL UDFs:
#
# - HERMES_ENC_SINGULAR_BFV: encrypts a plaintext integer
# - HERMES_DEC_SINGULAR_BFV: decrypts a BFV ciphertext
# - HERMES_SUM_BFV_DECRYPTED: decrypts and aggregates across rows
# - HERMES_MUL_BFV: multiplies two ciphertexts (BFV × BFV)
# - HERMES_MUL_SCALAR_BFV: multiplies ciphertext by a scalar (BFV × scalar)
#
# Note: Run this script from the project root.
# ============================================================

set -e

# Use environment variable to suppress MySQL password warning
export MYSQL_PWD="hpdic2023"

MYSQL_USER="hpdic"
PLUGIN_NAME="libhermes_udf.so"
PLUGIN_PATH="/usr/lib/mysql/plugin/${PLUGIN_NAME}"
PROJECT_ROOT="/home/cc/hermes"
BUILD_DIR="${PROJECT_ROOT}/build"

echo "[*] Compiling HERMES UDF plugin into $BUILD_DIR ..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
cmake "$PROJECT_ROOT" -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd "$PROJECT_ROOT"

echo "[*] Copying plugin to MySQL directory..."
sudo cp -v "$BUILD_DIR/$PLUGIN_NAME" "$PLUGIN_PATH"

echo "[*] Restarting MySQL to clear previous UDF state..."
sudo systemctl restart mysql
sleep 1

echo "[*] Registering UDF functions..."
mysql -u "$MYSQL_USER" <<EOF
DROP FUNCTION IF EXISTS HERMES_ENC_SINGULAR_BFV;
DROP FUNCTION IF EXISTS HERMES_DEC_SINGULAR_BFV;
DROP FUNCTION IF EXISTS HERMES_SUM_BFV;
DROP FUNCTION IF EXISTS HERMES_MUL_BFV;
DROP FUNCTION IF EXISTS HERMES_MUL_SCALAR_BFV;

CREATE FUNCTION HERMES_ENC_SINGULAR_BFV RETURNS STRING SONAME '$PLUGIN_NAME';
CREATE FUNCTION HERMES_DEC_SINGULAR_BFV RETURNS INTEGER SONAME '$PLUGIN_NAME';
CREATE AGGREGATE FUNCTION HERMES_SUM_BFV RETURNS INTEGER SONAME '$PLUGIN_NAME';
CREATE FUNCTION HERMES_MUL_BFV RETURNS STRING SONAME '$PLUGIN_NAME';
CREATE FUNCTION HERMES_MUL_SCALAR_BFV RETURNS STRING SONAME '$PLUGIN_NAME';
EOF

echo "[✓] Build and UDF registration complete. You may now run ./script/run.sh"