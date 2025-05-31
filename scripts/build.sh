#!/bin/bash
# ============================================================
# build.sh — Build and Register Hermes MySQL UDF Plugins
# Author: Dr. Dongfang Zhao (dzhao@cs.washington.edu)
# Last Updated: 2025-05-29
#
# This script compiles the Hermes plugins (based on OpenFHE),
# installs them to the MySQL plugin directory, restarts MySQL
# to clear previous UDF state, and registers the following
# homomorphic encryption functions as native SQL UDFs:
#
# Plugin: libhermes_udf.so
#   - HERMES_ENC_SINGULAR_BFV
#   - HERMES_DEC_SINGULAR_BFV
#   - HERMES_SUM_BFV_DECRYPTED
#   - HERMES_MUL_BFV
#   - HERMES_MUL_SCALAR_BFV
#
# Plugin: libhermes_pack_convert.so
#   - HERMES_PACK_CONVERT (aggregate)
#
# Note: Run this script from the project root.
# ============================================================

set -e

export MYSQL_PWD="hpdic2023"
MYSQL_USER="hpdic"

PROJECT_ROOT="/home/cc/hermes"
BUILD_DIR="${PROJECT_ROOT}/build"
PLUGIN_DIR="/usr/lib/mysql/plugin"

UDF1_NAME="libhermes_udf.so"
UDF2_NAME="libhermes_pack_convert.so"
UDF3_NAME="libhermes_packsum.so"

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
DROP FUNCTION IF EXISTS HERMES_DEC_VECTOR_BFV;
DROP FUNCTION IF EXISTS HERMES_PACK_GROUP_SUM;
DROP FUNCTION IF EXISTS HERMES_PACK_GLOBAL_SUM;
DROP FUNCTION IF EXISTS HERMES_DEC_SINGULAR;


CREATE FUNCTION HERMES_ENC_SINGULAR_BFV RETURNS STRING SONAME '$UDF1_NAME';
CREATE FUNCTION HERMES_DEC_SINGULAR_BFV RETURNS INTEGER SONAME '$UDF1_NAME';
CREATE AGGREGATE FUNCTION HERMES_SUM_BFV RETURNS INTEGER SONAME '$UDF1_NAME';
CREATE FUNCTION HERMES_MUL_BFV RETURNS STRING SONAME '$UDF1_NAME';
CREATE FUNCTION HERMES_MUL_SCALAR_BFV RETURNS STRING SONAME '$UDF1_NAME';

CREATE AGGREGATE FUNCTION HERMES_PACK_CONVERT RETURNS STRING SONAME '$UDF2_NAME';
CREATE FUNCTION HERMES_DEC_VECTOR_BFV RETURNS STRING SONAME '$UDF2_NAME';

CREATE AGGREGATE FUNCTION HERMES_PACK_GROUP_SUM RETURNS STRING SONAME '$UDF3_NAME';
CREATE FUNCTION HERMES_PACK_GLOBAL_SUM RETURNS STRING SONAME '$UDF3_NAME';
CREATE FUNCTION HERMES_DEC_SINGULAR RETURNS INTEGER SONAME '$UDF3_NAME';
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