#!/bin/bash
set -e

export MYSQL_PWD="hpdic2023"
MYSQL_USER="hpdic"
MYSQL_DB="hermes_apps"

if [[ -z "$1" ]]; then
  echo "Usage: $0 <table_name>"
  exit 1
fi

TABLE="$1"
PREFIX="${TABLE#tbl_}"  # e.g., tbl_bitcoin → bitcoin
OUT_DIR="./experiments/result"
mkdir -p "$OUT_DIR"
OUT_FILE="${OUT_DIR}/load_${TABLE}.txt"

echo "[*] Running loading experiment on table: $TABLE" | tee "$OUT_FILE"
total_rows=$(mysql -u "$MYSQL_USER" -D "$MYSQL_DB" -sN -e "SELECT COUNT(*) FROM $TABLE;")
echo "[*] Total rows: $total_rows" | tee -a "$OUT_FILE"

#######################################
# Pack-based encryption timing
#######################################
echo "[*] Timing HERMES_PACK_CONVERT (group-wise)..." | tee -a "$OUT_FILE"

group_ids=$(mysql -u "$MYSQL_USER" -D "$MYSQL_DB" -sN -e "SELECT DISTINCT group_id FROM $TABLE ORDER BY group_id;")

start_pack=$(date +%s%3N)

for gid in $group_ids; do
  if [[ "$TABLE" == "tbl_bitcoin" ]]; then
    mysql -u "$MYSQL_USER" -D "$MYSQL_DB" -e "
      SELECT HERMES_PACK_CONVERT(FLOOR(value / 24)) FROM $TABLE WHERE group_id = $gid;" > /dev/null
  else
    mysql -u "$MYSQL_USER" -D "$MYSQL_DB" -e "
      SELECT HERMES_PACK_CONVERT(value) FROM $TABLE WHERE group_id = $gid;" > /dev/null
  fi
done

end_pack=$(date +%s%3N)
elapsed_pack=$((end_pack - start_pack))

echo "PACKED: total=${elapsed_pack} ms" | tee -a "$OUT_FILE"

#######################################
# Singular encryption timing
#######################################
echo "[*] Timing HERMES_ENC_SINGULAR (bulk SELECT)..." | tee -a "$OUT_FILE"

start_sing=$(date +%s%3N)

if [[ "$TABLE" == "tbl_bitcoin" ]]; then
  mysql -u "$MYSQL_USER" -D "$MYSQL_DB" -e "
    SELECT HERMES_ENC_SINGULAR(FLOOR(value / 24)) FROM $TABLE;" > /dev/null
else
  mysql -u "$MYSQL_USER" -D "$MYSQL_DB" -e "
    SELECT HERMES_ENC_SINGULAR(value) FROM $TABLE;" > /dev/null
fi

end_sing=$(date +%s%3N)
elapsed_sing=$((end_sing - start_sing))

echo "SINGULAR: total=${elapsed_sing} ms" | tee -a "$OUT_FILE"

#######################################
# Summary
#######################################
echo "" | tee -a "$OUT_FILE"
echo "------ Summary (table: $TABLE) ------" | tee -a "$OUT_FILE"
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$OUT_FILE"
echo "Host: $(hostname)" | tee -a "$OUT_FILE"
echo "Kernel: $(uname -r)" | tee -a "$OUT_FILE"
echo "Total tuples: $total_rows" | tee -a "$OUT_FILE"
echo "Packed Encrypt:   $elapsed_pack ms (avg: $((elapsed_pack * 1000 / total_rows)) µs/row)" | tee -a "$OUT_FILE"
echo "Singular Encrypt: $elapsed_sing ms (avg: $((elapsed_sing * 1000 / total_rows)) µs/row)" | tee -a "$OUT_FILE"