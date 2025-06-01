#!/bin/bash
# ========================================================================
# File: script/build.sh
# ------------------------------------------------------------------------
# HERMES Plugin Build and UDF Registration Script
#
# FUNCTIONALITY:
# ------------------------------------------------------------------------
# This script builds and installs all HERMES MySQL UDF plugins, including:
#
#   1. Compilation of source code via CMake and Make.
#   2. Copying shared libraries to MySQL's plugin directory.
#   3. Restarting the MySQL server to reset UDF loading state.
#   4. Registering all HERMES functions and aggregate functions.
#   5. Generating BFV keypair (public + secret) under /tmp/hermes/.
#
# SUPPORTED PLUGINS AND UDFS:
# ------------------------------------------------------------------------
# Plugin: libhermes_udf.so
#   - HERMES_ENC_SINGULAR_BFV
#   - HERMES_DEC_SINGULAR_BFV
#   - HERMES_SUM_BFV
#   - HERMES_MUL_BFV
#   - HERMES_MUL_SCALAR_BFV
#
# Plugin: libhermes_pack_convert.so
#   - HERMES_PACK_CONVERT (aggregate)
#   - HERMES_DEC_VECTOR
#
# Plugin: libhermes_packsum.so
#   - HERMES_PACK_GROUP_SUM (aggregate)
#   - HERMES_PACK_GLOBAL_SUM (aggregate)
#   - HERMES_DEC_SINGULAR
#
# IMPORTANT NOTES:
# ------------------------------------------------------------------------
# ⚠️  All UDFs using OpenFHE encryption/decryption must reside in the
#     *same shared object (.so)* to ensure consistent CryptoContext state.
#
#     Even if `makeBfvContext()` is called with the same parameters,
#     OpenFHE may produce structurally incompatible contexts across .so
#     boundaries due to internal randomness during context construction.
#
# ✅  This script ensures that each function is registered with the correct
#     originating plugin and reuses shared contexts via `getGC()` internally.
#
# DEPENDENCIES:
#   - MySQL server with UDF plugin loading enabled
#   - OpenFHE v1.2.4 (linked at build time)
#   - Writable /tmp/hermes/ for key storage
#
# AUTHOR:
#   Dr. Dongfang Zhao (dzhao@cs.washington.edu)
#   University of Washington
#   Last Updated: May 31, 2025
# ========================================================================

set -e

export MYSQL_PWD="hpdic2023"
MYSQL_USER="hpdic"

PROJECT_ROOT="/home/cc/hermes"
BUILD_DIR="${PROJECT_ROOT}/build"
PLUGIN_DIR="/usr/lib/mysql/plugin"

UDF1_NAME="libhermes_udf.so"
UDF2_NAME="libhermes_pack_convert.so"
UDF3_NAME="libhermes_packsum.so"
UDF4_NAME="libhermes_packupdate.so"

echo "[*] Compiling all HERMES plugins into $BUILD_DIR ..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
cmake "$PROJECT_ROOT" -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd "$PROJECT_ROOT"

echo "[*] Copying shared libraries to MySQL plugin directory..."
sudo cp -v "$BUILD_DIR/$UDF1_NAME" "$PLUGIN_DIR"
sudo cp -v "$BUILD_DIR/src/pack/$UDF2_NAME" "$PLUGIN_DIR"
sudo cp -v "$BUILD_DIR/src/pack/$UDF3_NAME" "$PLUGIN_DIR"
sudo cp -v "$BUILD_DIR/src/pack/$UDF4_NAME" "$PLUGIN_DIR"

echo "[*] Restarting MySQL to reset UDF state..."
sudo systemctl restart mysql
sleep 1

echo "[*] Registering all UDF functions..."
mysql -u "$MYSQL_USER" <<EOF
DROP FUNCTION IF EXISTS HERMES_ENC_SINGULAR_BFV;
DROP FUNCTION IF EXISTS HERMES_DEC_SINGULAR_BFV;
DROP FUNCTION IF EXISTS HERMES_SUM_BFV;
DROP FUNCTION IF EXISTS HERMES_MUL_BFV;
DROP FUNCTION IF EXISTS HERMES_MUL_SCALAR_BFV;
DROP FUNCTION IF EXISTS HERMES_PACK_CONVERT;
DROP FUNCTION IF EXISTS HERMES_DEC_VECTOR;
DROP FUNCTION IF EXISTS HERMES_PACK_GROUP_SUM;
DROP FUNCTION IF EXISTS HERMES_PACK_GLOBAL_SUM;
DROP FUNCTION IF EXISTS HERMES_ENC_SINGULAR;
DROP FUNCTION IF EXISTS HERMES_DEC_SINGULAR;
DROP FUNCTION IF EXISTS HERMES_PACK_ADD;
DROP FUNCTION IF EXISTS HERMES_PACK_RMV;
DROP FUNCTION IF EXISTS HERMES_SUM_CIPHERS;


CREATE FUNCTION HERMES_ENC_SINGULAR_BFV RETURNS STRING SONAME '$UDF1_NAME';
CREATE FUNCTION HERMES_DEC_SINGULAR_BFV RETURNS INTEGER SONAME '$UDF1_NAME';
CREATE AGGREGATE FUNCTION HERMES_SUM_BFV RETURNS INTEGER SONAME '$UDF1_NAME';
CREATE FUNCTION HERMES_MUL_BFV RETURNS STRING SONAME '$UDF1_NAME';
CREATE FUNCTION HERMES_MUL_SCALAR_BFV RETURNS STRING SONAME '$UDF1_NAME';

CREATE AGGREGATE FUNCTION HERMES_PACK_CONVERT RETURNS STRING SONAME '$UDF2_NAME';
CREATE FUNCTION HERMES_DEC_VECTOR RETURNS STRING SONAME '$UDF2_NAME';

CREATE AGGREGATE FUNCTION HERMES_PACK_GROUP_SUM RETURNS STRING SONAME '$UDF3_NAME';
CREATE AGGREGATE FUNCTION HERMES_PACK_GLOBAL_SUM RETURNS STRING SONAME '$UDF3_NAME';
CREATE FUNCTION HERMES_ENC_SINGULAR RETURNS STRING SONAME '$UDF3_NAME';
CREATE FUNCTION HERMES_DEC_SINGULAR RETURNS INTEGER SONAME '$UDF3_NAME';

CREATE FUNCTION HERMES_PACK_ADD RETURNS STRING SONAME '$UDF4_NAME';
CREATE FUNCTION HERMES_PACK_RMV RETURNS STRING SONAME '$UDF4_NAME';
CREATE FUNCTION HERMES_SUM_CIPHERS RETURNS STRING SONAME '$UDF4_NAME';
EOF

echo "[✓] All plugins built and UDFs registered successfully."

# ============================================================
# Ensure key directory (/tmp/hermes) exists and is writable
# for gen_keys to dump the public/secret keys.
# We explicitly reset ownership to current user to avoid MySQL permission issues.
# ============================================================
KEY_DIR="/tmp/hermes"
if [ -d "$KEY_DIR" ]; then
  echo "[*] Cleaning up existing $KEY_DIR ..."
  sudo rm -rf "$KEY_DIR"
fi

echo "[*] Creating writable key directory at $KEY_DIR ..."
mkdir -p "$KEY_DIR"
chmod 755 "$KEY_DIR"
chown "$(whoami):$(whoami)" "$KEY_DIR"

echo "[*] Generating default BFV keypair to /tmp/hermes ..."
"$BUILD_DIR/gen_keys"