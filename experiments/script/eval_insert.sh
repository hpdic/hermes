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

PREFIX="${TABLE#tbl_}"  # e.g., tbl_bitcoin → bitcoin
PACK_TABLE="tbl_${PREFIX}_pack"
SINGULAR_TABLE="tbl_${PREFIX}_singular"
OUT_DIR="./experiments/result"
OUT_FILE="${OUT_DIR}/insert_${PREFIX}_${SIZE_PACK}.txt"

mkdir -p "$OUT_DIR"
echo "[*] Insert experiment on table: $TABLE" | tee "$OUT_FILE"

#######################################
# Step 1: Create temporary tables
#######################################
mysql -u "$MYSQL_USER" -D "$MYSQL_DB" <<EOF
DROP TABLE IF EXISTS $PACK_TABLE;
CREATE TABLE $PACK_TABLE (
  id INT PRIMARY KEY AUTO_INCREMENT,
  group_id INT,
  slot_count INT,
  ctxt_repr LONGTEXT
);

DROP TABLE IF EXISTS $SINGULAR_TABLE;
CREATE TABLE $SINGULAR_TABLE (
  id INT PRIMARY KEY AUTO_INCREMENT,
  value INT,
  ctxt_repr LONGTEXT
);
EOF

#######################################
# Step 2: Load group_id = 1 from source table
#######################################
echo "[*] Loading group_id = 1 data into temp tables..." | tee -a "$OUT_FILE"

if [[ "$PREFIX" == "bitcoin" ]]; then
  mysql -u "$MYSQL_USER" -D "$MYSQL_DB" -e "
    INSERT INTO $SINGULAR_TABLE(value, ctxt_repr)
    SELECT CAST(ROUND(value / 24) AS UNSIGNED), HERMES_ENC_SINGULAR(CAST(ROUND(value / 24) AS UNSIGNED))
    FROM $TABLE WHERE group_id = 1;"

  mysql -u "$MYSQL_USER" -D "$MYSQL_DB" -e "
    INSERT INTO $PACK_TABLE(group_id, slot_count, ctxt_repr)
    SELECT 1, count(*), HERMES_PACK_CONVERT(CAST(ROUND(value / 24) AS UNSIGNED))
    FROM $TABLE WHERE group_id = 1;"
else
  mysql -u "$MYSQL_USER" -D "$MYSQL_DB" -e "
    INSERT INTO $SINGULAR_TABLE(value, ctxt_repr)
    SELECT value, HERMES_ENC_SINGULAR(value)
    FROM $TABLE WHERE group_id = 1;"

  mysql -u "$MYSQL_USER" -D "$MYSQL_DB" -e "
    INSERT INTO $PACK_TABLE(group_id, slot_count, ctxt_repr)
    SELECT 1, count(*), HERMES_PACK_CONVERT(value)
    FROM $TABLE WHERE group_id = 1;"
fi

#######################################
# Step 3: Generate 100 inserts
#######################################
echo "[*] Generating 100 inserts..." | tee -a "$OUT_FILE"

# 读取 slot_count 值（假设只有一个 ciphertext，group_id = 1）
slot_count=$(mysql -N -B -u "$MYSQL_USER" -D "$MYSQL_DB" -e "
  SELECT slot_count FROM $PACK_TABLE WHERE group_id = 1 LIMIT 1;")

if [[ -z "$slot_count" ]]; then
  echo "Error: slot_count not found for group_id = 1"
  exit 1
fi

insert_pack=""
insert_singular=""

for ((i = 0; i < 100; i++)); do
  val=$((10 + RANDOM % 990))
  slot=$((slot_count + i))  # Always insert into the next slot after the last used slot
  insert_pack+="SELECT HERMES_PACK_ADD(ctxt_repr, $slot, $val) FROM $PACK_TABLE WHERE group_id = 1;\n"
  insert_singular+="INSERT INTO $SINGULAR_TABLE(value, ctxt_repr) VALUES ($val, HERMES_ENC_SINGULAR($val));\n"
done

#######################################
# Step 4: Time PACK INSERT
#######################################
echo "[*] Running PACK inserts..." | tee -a "$OUT_FILE"
start_pack=$(date +%s%3N)
echo -e "$insert_pack" | mysql -u "$MYSQL_USER" -D "$MYSQL_DB" > /dev/null
end_pack=$(date +%s%3N)
elapsed_pack=$((end_pack - start_pack))
echo "PACK-INSERT: total=${elapsed_pack} ms" | tee -a "$OUT_FILE"

new_slot_count=$((slot_count + 100))
mysql -u "$MYSQL_USER" -D "$MYSQL_DB" -e "
  UPDATE $PACK_TABLE SET slot_count = $new_slot_count WHERE group_id = 1;"

#######################################
# Step 5: Time SINGULAR INSERT
#######################################
echo "[*] Running SINGULAR inserts..." | tee -a "$OUT_FILE"
start_sing=$(date +%s%3N)
echo -e "$insert_singular" | mysql -u "$MYSQL_USER" -D "$MYSQL_DB" > /dev/null
end_sing=$(date +%s%3N)
elapsed_sing=$((end_sing - start_sing))
echo "SINGULAR-INSERT: total=${elapsed_sing} ms" | tee -a "$OUT_FILE"

#######################################
# Summary
#######################################
echo "" | tee -a "$OUT_FILE"
echo "------ Summary (insert eval on $TABLE, group_id=1) ------" | tee -a "$OUT_FILE"
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$OUT_FILE"
echo "Host: $(hostname)" | tee -a "$OUT_FILE"
echo "Kernel: $(uname -r)" | tee -a "$OUT_FILE"
echo "Packed Insert:   $elapsed_pack ms (avg: $((elapsed_pack * 1000 / 100)) µs/op)" | tee -a "$OUT_FILE"
echo "Singular Insert: $elapsed_sing ms (avg: $((elapsed_sing * 1000 / 100)) µs/op)" | tee -a "$OUT_FILE"