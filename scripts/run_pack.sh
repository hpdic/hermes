#!/bin/bash
#
# File: script/run_pack.sh
# --------------------------------------------------------------------
# HERMES End-to-End Test Script for Encrypted Packing and Aggregation
#
# FUNCTIONALITY:
# --------------------------------------------------------------------
# This script performs a full test of HERMES's encrypted packing and
# aggregation capabilities over a realistic employee salary table.
#
# Specifically, it exercises:
#
# 1. HERMES_PACK_CONVERT:
#    - Packs all salaries in each department into a ciphertext.
#
# 2. HERMES_DEC_VECTOR_BFV:
#    - Decrypts the packed vector to verify correct packing.
#
# 3. HERMES_PACK_GROUP_SUM:
#    - Computes encrypted local sum of salaries per department using BFV.
#
# 4. HERMES_DEC_SINGULAR:
#    - Decrypts scalar ciphertexts produced by group sums.
#
# 5. HERMES_PACK_GLOBAL_SUM:
#    - Aggregates the local sum ciphertexts into a global encrypted total.
#
# USAGE NOTES:
# --------------------------------------------------------------------
# - All UDFs must be pre-registered and implemented within the *same*
#   shared object (.so) file due to OpenFHE context compatibility issues.
#
# - This script writes diagnostic markers to MySQL error log for traceability.
# - Sample employee records are inserted and grouped by `dept`.
#
# DEPENDENCIES:
#   - MySQL UDFs from the HERMES project
#   - OpenFHE v1.2.4 runtime
#   - MySQL server with access to hpdic_db and user: hpdic / password: hpdic2023
#
# AUTHOR:
#   Dongfang Zhao (dzhao@cs.washington.edu)
#   University of Washington
#   Last Updated: May 31, 2025

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
  packed_ct LONGBLOB
);

INSERT INTO packed_salaries
SELECT dept, HERMES_PACK_CONVERT(salary)
FROM employees
GROUP BY dept;
EOF

echo "[+] Inserted packed ciphertexts into 'packed_salaries'."

# 5. Decrypt to preview the vector value
echo "[*] Decrypting packed ciphertexts..."
$MYSQL -e "
SELECT dept,
       CAST(HERMES_DEC_VECTOR_BFV(packed_ct) AS CHAR) AS first_salary_in_group
FROM packed_salaries;
"

# 6. Compute encrypted local sum per group
echo "[*] Computing encrypted local sum per group..."
$MYSQL <<EOF
DROP TABLE IF EXISTS packed_sums;
CREATE TABLE packed_sums (
  dept INT,
  local_sum_ct LONGBLOB
);

INSERT INTO packed_sums
SELECT dept, HERMES_PACK_GROUP_SUM(salary)
FROM employees
GROUP BY dept;
EOF

echo "[+] Inserted encrypted local sums into 'packed_sums'."

# Optional: Decrypt and check each group's local sum in plaintext
echo "[*] Decrypting local group sums..."
$MYSQL -e "
SELECT dept,
       CAST(HERMES_DEC_SINGULAR(local_sum_ct) AS CHAR) AS local_sum
FROM packed_sums;
"

# 7. Compute global sum (homomorphic sum of local group sums)
echo "[*] Computing global sum (homomorphic sum of local group sums)..."
$MYSQL <<EOF
DROP TABLE IF EXISTS global_sum;
CREATE TABLE global_sum (
  result_ct LONGBLOB
);

INSERT INTO global_sum
SELECT HERMES_PACK_GLOBAL_SUM(local_sum_ct) FROM packed_sums;
EOF

echo "[+] Computed global ciphertext sum."

# Decrypt global sum
echo "[*] Decrypting global sum..."
$MYSQL -e "
SELECT CAST(HERMES_DEC_SINGULAR(result_ct) AS CHAR) AS global_sum
FROM global_sum;
"