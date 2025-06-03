#!/bin/bash
set -e

export MYSQL_PWD="hpdic2023"
MYSQL_USER="hpdic"
MYSQL_DB="hermes_apps"

# Paths to sub-scripts
CONVERT_SCRIPT="./experiments/script/convert_csv.sh"
LOAD_SCRIPT="./experiments/script/load_csv.sh"
ENCRYPT_SCRIPT="./experiments/script/eval_encrypt.sh"
INSERT_SCRIPT="./experiments/script/eval_insert.sh"
REMOVE_SCRIPT="./experiments/script/eval_remove.sh"

# Dataset table names (must match those loaded in DB)
DATASETS=("tbl_covid19" "tbl_bitcoin" "tbl_hg38")

echo "[*] Starting full Hermes evaluation..."

#######################################
# Step 0a: Convert raw data to CSV
#######################################
echo ""
echo "[=] Step 0a: Converting raw data to CSV..."
bash "$CONVERT_SCRIPT"

#######################################
# Step 0b: Load CSV into MySQL
#######################################
echo ""
echo "[=] Step 0b: Loading CSV into MySQL..."
bash "$LOAD_SCRIPT"

#######################################
# Step 1: Encryption
#######################################
echo ""
echo "[=] Step 1: Encryption Experiments"
for TABLE in "${DATASETS[@]}"; do
  echo ""
  echo "[+] Running encryption on $TABLE"
  bash "$ENCRYPT_SCRIPT" "$TABLE"
done

#######################################
# Step 2: Insert
#######################################
echo ""
echo "[=] Step 2: Insert Experiments"
for TABLE in "${DATASETS[@]}"; do
  echo ""
  echo "[+] Running insert on $TABLE"
  bash "$INSERT_SCRIPT" "$TABLE"
done

#######################################
# Step 3: Remove
#######################################
echo ""
echo "[=] Step 3: Remove Experiments"
for TABLE in "${DATASETS[@]}"; do
  echo ""
  echo "[+] Running remove on $TABLE"
  bash "$REMOVE_SCRIPT" "$TABLE"
done

echo ""
echo "[✓] All experiments completed successfully."