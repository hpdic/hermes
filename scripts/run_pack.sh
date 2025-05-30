#!/bin/bash
#
# File: run_pack.sh
# ------------------------------------------------------------
# HERMES Packing UDF Test Script
# This script sets up a realistic employee table,
# invokes the HERMES_PACK_CONVERT() aggregate UDF,
# and displays a truncated preview of the encrypted output.
#
# Author: Dongfang Zhao (dzhao@cs.washington.edu)
# Institution: University of Washington
# Last Updated: May 29, 2025

set -euo pipefail

echo "[*] Running HERMES_PACK_CONVERT aggregation test..."

export MYSQL_PWD="hpdic2023"
MYSQL="mysql -u hpdic -D hpdic_db"

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
       HERMES_DEC_VECTOR_BFV(packed_ct) AS first_salary_in_group
FROM packed_salaries;
"