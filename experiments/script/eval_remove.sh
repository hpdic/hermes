#!/bin/bash
set -e

export MYSQL_PWD="hpdic2023"
MYSQL_USER="hpdic"
MYSQL_DB="hermes_apps"

if [[ -z "$1" || -z "$2" ]]; then
  echo "Usage: $0 <table_name> <pack_size>"
  echo "  <pack_size> must be a positive integer ≤ 8192."
  echo "  ⚠️ Note: Although 8192 is the maximum, we recommend using 4096 or smaller for performance and memory stability."
  exit 1
fi
TABLE="$1"
SIZE_PACK="$2"

PREFIX="${TABLE#tbl_}"
PACK_TABLE="tbl_${PREFIX}_pack"
SINGULAR_TABLE="tbl_${PREFIX}_singular"
OUT_DIR="./experiments/result"
OUT_FILE="${OUT_DIR}/scale_${SIZE_PACK}/remove_${PREFIX}.txt"

mkdir -p "$OUT_DIR"
echo "[*] Remove experiment on table: $TABLE" | tee "$OUT_FILE"

#######################################
# Step 1: Assume temporary tables already exist from previous insert test
#######################################

#######################################
# Step 2: Generate 100 deletes
#######################################
echo "[*] Generating 100 deletes..." | tee -a "$OUT_FILE"

# Retrieve slot count
slot_count=$(mysql -N -u "$MYSQL_USER" -D "$MYSQL_DB" -e \
  "SELECT slot_count FROM $PACK_TABLE WHERE group_id = 1 LIMIT 1;")

if (( slot_count <= 1 )); then
  echo "[!] Not enough slots to perform deletion." | tee -a "$OUT_FILE"
  exit 1
fi

remove_pack=""
k=$slot_count  
for ((i = 0; i < 100; i++)); do
  slot=$((RANDOM % (slot_count - 2)))
  remove_pack+="SELECT HERMES_PACK_RMV(ctxt_repr, $slot, $k) FROM $PACK_TABLE WHERE group_id = 1;\n"
  ((k--))  
done

# Get first 100 IDs from singular table (ascending order)
ids_to_delete=$(mysql -u "$MYSQL_USER" -D "$MYSQL_DB" -sN -e "
  SELECT id FROM $SINGULAR_TABLE ORDER BY id ASC LIMIT 100;")
remove_singular=""
for id in $ids_to_delete; do
  remove_singular+="DELETE FROM $SINGULAR_TABLE WHERE id = $id;\n"
done

#######################################
# Step 3: Time PACK REMOVE
#######################################
echo "[*] Running PACK removes..." | tee -a "$OUT_FILE"
start_pack=$(date +%s%3N)
echo -e "$remove_pack" | mysql -u "$MYSQL_USER" -D "$MYSQL_DB" > /dev/null
end_pack=$(date +%s%3N)
elapsed_pack=$((end_pack - start_pack))
echo "PACK-REMOVE: total=${elapsed_pack} ms" | tee -a "$OUT_FILE"
# 最后统一更新 slot_count
mysql -u "$MYSQL_USER" -D "$MYSQL_DB" -e \
  "UPDATE $PACK_TABLE SET slot_count = slot_count - 100 WHERE group_id = 1;"

#######################################
# Step 4: Time SINGULAR DELETE
#######################################
echo "[*] Running SINGULAR deletes..." | tee -a "$OUT_FILE"
start_sing=$(date +%s%3N)
echo -e "$remove_singular" | mysql -u "$MYSQL_USER" -D "$MYSQL_DB" > /dev/null
end_sing=$(date +%s%3N)
elapsed_sing=$((end_sing - start_sing))
echo "SINGULAR-REMOVE: total=${elapsed_sing} ms" | tee -a "$OUT_FILE"

#######################################
# Summary
#######################################
echo "" | tee -a "$OUT_FILE"
echo "------ Summary (remove eval on $TABLE, group_id=1) ------" | tee -a "$OUT_FILE"
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$OUT_FILE"
echo "Host: $(hostname)" | tee -a "$OUT_FILE"
echo "Kernel: $(uname -r)" | tee -a "$OUT_FILE"
echo "Packed Remove:   $elapsed_pack ms (avg: $((elapsed_pack * 1000 / 100)) µs/op)" | tee -a "$OUT_FILE"
echo "Singular Remove: $elapsed_sing ms (avg: $((elapsed_sing * 1000 / 100)) µs/op)" | tee -a "$OUT_FILE"