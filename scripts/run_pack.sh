#!/bin/bash
#
# File: script/run_pack.sh
# --------------------------------------------------------------------
# HERMES End-to-End Test Script for Encrypted Packing and Aggregation
#
# FUNCTIONALITY:
# --------------------------------------------------------------------
# This script runs a full integration test of HERMES’s encrypted vector
# packing and aggregation capabilities using a realistic employee table.
#
# Covered UDFs:
# 1. HERMES_PACK_CONVERT:
#    - Packs all salaries within each department into a BFV ciphertext.
#
# 2. HERMES_DEC_VECTOR:
#    - Decrypts packed ciphertexts to verify per-slot encoding.
#
# 3. HERMES_PACK_GROUP_SUM:
#    - Computes encrypted group sums per department.
#
# 4. HERMES_DEC_SINGULAR:
#    - Decrypts scalar (summation) ciphertexts to recover integer totals.
#
# 5. HERMES_PACK_GLOBAL_SUM:
#    - Aggregates all group ciphertexts into a global sum ciphertext.
#
# 6. HERMES_PACK_ADD:
#    - Inserts a new value into a specific slot of a packed ciphertext.
#
# 7. HERMES_PACK_RMV:
#    - Removes a value from a specific slot of a packed ciphertext.
#
# USAGE NOTES:
# --------------------------------------------------------------------
# - All UDFs must reside in the same .so file to share encryption context.
# - MySQL writes test-phase markers to the error log for debugging.
# - Example table groups salaries by department (`dept`) column.
#
# DEPENDENCIES:
#   - HERMES MySQL UDF plugin (compiled and registered)
#   - OpenFHE v1.2.4 runtime
#   - MySQL 8+ server with test database `hpdic_db`
#   - User: hpdic / Password: hpdic2023
#
# AUTHOR:
#   Dongfang Zhao (dzhao@cs.washington.edu)
#   University of Washington
#   Last Updated: June 2, 2025

set -euo pipefail

export MYSQL_PWD="hpdic2023"
MYSQL="mysql -u hpdic -D hpdic_db"

# 0. Write start-of-test marker to MySQL error log
TIMESTAMP=$(date "+%F %T")
echo -e "\n[HERMES-TEST] === NEW HERMES PACK TEST @ $TIMESTAMP ===" | sudo tee -a /var/log/mysql/error.log

# 1. Create employee table
$MYSQL <<EOF
DROP TABLE IF EXISTS employees;
CREATE TABLE employees (
  eid INT,
  dept INT,
  salary INT
);
EOF

echo "[+] Created table 'employees'."

# 2. Insert realistic data
$MYSQL <<EOF
INSERT INTO employees VALUES
(1, 1, 1000),
(2, 1, 2000),
(3, 1, 1500),
(4, 2, 3000),
(5, 2, 2500);
EOF

echo "[+] Inserted sample employee records."

# 3. Run packing and preview first 8 hex characters of ciphertext
echo "[*] Packing salaries per department..."
$MYSQL -e "
SELECT dept,
       LEFT(HEX(HERMES_PACK_CONVERT(salary)), 8) AS encrypted_preview
FROM employees
GROUP BY dept;
"

# 4. Insert encrypted results into a new table for verification
$MYSQL <<EOF
DROP TABLE IF EXISTS packed_salaries;
CREATE TABLE packed_salaries (
  dept INT,
  slot_count INT,      
  packed_ct LONGBLOB  
);

INSERT INTO packed_salaries
SELECT
  dept,
  COUNT(salary) AS slot_count,       
  HERMES_PACK_CONVERT(salary) AS packed_ct
FROM employees
GROUP BY dept;
EOF

echo "[+] Inserted packed ciphertexts into 'packed_salaries' with slot counts."

# 5. Decrypt to preview the vector value
echo "[*] Decrypting packed ciphertexts..."
$MYSQL -e "
SELECT dept,
       slot_count,
       CAST(HERMES_DEC_VECTOR(packed_ct, slot_count) AS CHAR) AS salary_vector
FROM packed_salaries;
"

# 6. Compute encrypted local sum per group (in-place update)
echo "[*] Adding 'local_sum_ct' column to packed_salaries..."
$MYSQL -e "
  ALTER TABLE packed_salaries
  ADD COLUMN local_sum_ct LONGBLOB;
"

echo "[*] Computing and storing encrypted local sum for each group..."
$MYSQL -e "
  UPDATE packed_salaries ps
  SET ps.local_sum_ct = (
    SELECT HERMES_PACK_GROUP_SUM(salary)
    FROM employees e
    WHERE e.dept = ps.dept
  );
"

echo "[+] Encrypted local sums written into 'packed_salaries.local_sum_ct'."

# Optional: Decrypt and check each group's local sum
echo "[*] Decrypting local group sums..."
$MYSQL -e "
SELECT dept, 
       slot_count, 
       CAST(HERMES_DEC_VECTOR(packed_ct, slot_count) AS CHAR) AS salary_vector,
       CAST(HERMES_DEC_SINGULAR(local_sum_ct) AS CHAR) AS local_sum
FROM packed_salaries;
"

# 7. Compute global sum (homomorphic sum of local group sums)
echo "[*] Computing global sum (homomorphic sum of local group sums)..."
$MYSQL <<EOF
DROP TABLE IF EXISTS global_sum;
CREATE TABLE global_sum (
  result_ct LONGBLOB
);

INSERT INTO global_sum
SELECT HERMES_PACK_GLOBAL_SUM(local_sum_ct) FROM packed_salaries;
EOF

echo "[+] Computed global ciphertext sum."

# Decrypt global sum
echo "[*] Decrypting global sum..."
$MYSQL -e "
SELECT CAST(HERMES_DEC_SINGULAR(result_ct) AS CHAR) AS global_sum
FROM global_sum;
"

# 8. In-place insertion of a new value into packed ciphertext
echo "[*] Testing HERMES_PACK_ADD ..."

# -- Perform three updates in-place:
#    ① Update packed_ct by homomorphically inserting 9999 into slot[3]
#    ② Update local_sum_ct via homomorphic ciphertext addition
#    ③ Increment slot_count by 1
$MYSQL -e "
UPDATE packed_salaries
SET
  packed_ct = HERMES_PACK_ADD(packed_ct, 9999, 3),
  local_sum_ct = HERMES_SUM_CIPHERS(local_sum_ct, HERMES_ENC_SINGULAR(9999)),
  slot_count = slot_count + 1
WHERE dept = 1;
"

# -- Decrypt and verify:
#    - packed_ct should contain: 1000, 2000, 1500, 9999
#    - local_sum_ct should equal: 14499
$MYSQL -e "
SELECT dept,
       slot_count,
       CAST(HERMES_DEC_VECTOR(packed_ct, slot_count) AS CHAR) AS updated_vector,
       CAST(HERMES_DEC_SINGULAR(local_sum_ct) AS CHAR) AS updated_sum
FROM packed_salaries
WHERE dept = 1;
"

# 9. Delete a value from a packed ciphertext (slot-wise)
echo "[*] Testing HERMES_PACK_RMV ..."

$MYSQL -e "
UPDATE packed_salaries
SET
  packed_ct = HERMES_PACK_RMV(packed_ct, 1, slot_count),
  local_sum_ct = HERMES_SUM_CIPHERS(local_sum_ct, HERMES_ENC_SINGULAR(-2000)),
  slot_count = slot_count - 1
WHERE dept = 1;
"

# Preview after deletion
$MYSQL -e "
SELECT dept,
       slot_count,
       CAST(HERMES_DEC_VECTOR(packed_ct, slot_count) AS CHAR) AS updated_vector,
       CAST(HERMES_DEC_SINGULAR(local_sum_ct) AS CHAR) AS updated_sum
FROM packed_salaries
WHERE dept = 1;
"