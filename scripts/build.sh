#!/bin/bash
# ============================================================
# build.sh — Build and Register Hermes MySQL UDF Plugin
# Author: Dr. Dongfang Zhao (dzhao@cs.washington.edu)
# Last Updated: 2025-05-26
#
# This script compiles the Hermes plugin (based on OpenFHE),
# installs it to the MySQL plugin directory, restarts MySQL
# to clear previous UDF state, and registers the homomorphic
# encryption functions as native SQL UDFs.
#
# Note: Run this script from the project root.
# ============================================================

set -e

MYSQL_USER="hpdic"
MYSQL_PASS="hpdic2023"
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
mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" <<EOF
DROP FUNCTION IF EXISTS HERMES_ENC_SINGULAR_BFV;
DROP FUNCTION IF EXISTS HERMES_DEC_SINGULAR_BFV;
DROP FUNCTION IF EXISTS HERMES_SUM_BFV;
DROP FUNCTION IF EXISTS HERMES_MUL_BFV;

CREATE FUNCTION HERMES_ENC_SINGULAR_BFV RETURNS STRING SONAME '$PLUGIN_NAME';
CREATE FUNCTION HERMES_DEC_SINGULAR_BFV RETURNS INTEGER SONAME '$PLUGIN_NAME';
CREATE AGGREGATE FUNCTION HERMES_SUM_BFV RETURNS INTEGER SONAME '$PLUGIN_NAME';
CREATE FUNCTION HERMES_MUL_BFV RETURNS STRING SONAME '$PLUGIN_NAME';
EOF

echo "[✓] Build and UDF registration complete. You may now run ./script/run.sh"