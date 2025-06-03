#!/bin/bash
set -e

export MYSQL_PWD="hpdic2023"
MYSQL_USER="hpdic"
MYSQL_DB="hermes_apps"

if [[ -z "$1" ]]; then
  echo "Usage: $0 <table_name> (e.g., tbl_covid19)"
  exit 1
fi

TABLE="$1"
PREFIX="${TABLE#tbl_}"
PACK_TABLE="tbl_${PREFIX}_pack"
SINGULAR_TABLE="tbl_${PREFIX}_singular"
OUT_DIR="./experiments/result"
OUT_FILE="${OUT_DIR}/remove_${PREFIX}.txt"
ORIGINAL_GROUP_SIZE=8192

mkdir -p "$OUT_DIR"
echo "[*] Remove experiment on table: $TABLE" | tee -a "$OUT_FILE"

#######################################
# Step 1: Assume temporary tables already exist from previous insert test
#######################################

#######################################
# Step 2: Generate 100 deletes
#######################################
echo "[*] Generating 100 deletes..." | tee -a "$OUT_FILE"

remove_pack=""
remove_singular=""

k=$ORIGINAL_GROUP_SIZE
for ((i = 0; i < 100; i++)); do
  slot=$((RANDOM % (k - 1)))
  remove_pack+="SELECT HERMES_PACK_RMV(ctxt_repr, $slot, $k) FROM $PACK_TABLE WHERE group_id = 1;\n"
  ((k--))
done

# Get first 100 IDs from singular table (ascending order)
ids_to_delete=$(mysql -u "$MYSQL_USER" -D "$MYSQL_DB" -sN -e "
  SELECT id FROM $SINGULAR_TABLE ORDER BY id ASC LIMIT 100;")

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