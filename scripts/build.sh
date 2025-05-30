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

echo "[*] Ensuring temporary runtime directory exists..."
TMP_RUNTIME_DIR="/tmp/hermes"
if [ ! -d "$TMP_RUNTIME_DIR" ]; then
  echo "[*] Creating $TMP_RUNTIME_DIR ..."
  sudo mkdir -p "$TMP_RUNTIME_DIR"
  sudo chown mysql:mysql "$TMP_RUNTIME_DIR"
  sudo chmod 755 "$TMP_RUNTIME_DIR"
else
  echo "[*] $TMP_RUNTIME_DIR already exists."
fi

export MYSQL_PWD="hpdic2023"
MYSQL_USER="hpdic"

PROJECT_ROOT="/home/cc/hermes"
BUILD_DIR="${PROJECT_ROOT}/build"
PLUGIN_DIR="/usr/lib/mysql/plugin"

UDF1_NAME="libhermes_udf.so"
UDF2_NAME="libhermes_pack_convert.so"

echo "[*] Compiling all HERMES plugins into $BUILD_DIR ..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
cmake "$PROJECT_ROOT" -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd "$PROJECT_ROOT"

echo "[*] Copying shared libraries to MySQL plugin directory..."
sudo cp -v "$BUILD_DIR/$UDF1_NAME" "$PLUGIN_DIR"
sudo cp -v "$BUILD_DIR/src/pack/$UDF2_NAME" "$PLUGIN_DIR"

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

CREATE FUNCTION HERMES_ENC_SINGULAR_BFV RETURNS STRING SONAME '$UDF1_NAME';
CREATE FUNCTION HERMES_DEC_SINGULAR_BFV RETURNS INTEGER SONAME '$UDF1_NAME';
CREATE AGGREGATE FUNCTION HERMES_SUM_BFV RETURNS INTEGER SONAME '$UDF1_NAME';
CREATE FUNCTION HERMES_MUL_BFV RETURNS STRING SONAME '$UDF1_NAME';
CREATE FUNCTION HERMES_MUL_SCALAR_BFV RETURNS STRING SONAME '$UDF1_NAME';

CREATE AGGREGATE FUNCTION HERMES_PACK_CONVERT RETURNS STRING SONAME '$UDF2_NAME';
CREATE FUNCTION HERMES_DEC_VECTOR_BFV RETURNS INTEGER SONAME '$UDF2_NAME';
EOF

echo "[✓] All plugins built and UDFs registered successfully."