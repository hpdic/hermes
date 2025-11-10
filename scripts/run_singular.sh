#!/bin/bash
# run_singular.sh — End-to-end test for Hermes MySQL UDFs with BFV encryption
# Author: Dongfang Zhao, dongfang.zhao@gmail.com
# Last Updated: November 9, 2025
#
# Usage: ./run_singular.sh
# This script tests the UDF plugin through encrypted SQL queries.

set -e

# Use environment variable to suppress MySQL password warning
export MYSQL_PWD="hpdic2023"

MYSQL_USER="hpdic"

echo "[*] Running encrypted SQL tests..."

mysql -u $MYSQL_USER <<EOF
-- ============================================================
-- 1. Setup: Create database and original employee table
-- ============================================================
EOF

echo -e "\n[1] Setting up test database and base employee table..."
mysql -u $MYSQL_USER <<EOF
CREATE DATABASE IF NOT EXISTS hpdic_db;
USE hpdic_db;

DROP TABLE IF EXISTS employee_grouped;
CREATE TABLE employee_grouped (
  id INT,
  name VARCHAR(50),
  department VARCHAR(32),
  salary INT
);

INSERT INTO employee_grouped VALUES
  (1, 'Alice', 'HR', 5200),
  (2, 'Bob',   'HR', 4800),
  (3, 'Carol', 'ENG', 6000),
  (4, 'Dave',  'ENG', 5900);
EOF

echo -e "\n[2] Encrypting salary values using HERMES_ENC_SINGULAR_BFV..."
mysql -u $MYSQL_USER <<EOF
USE hpdic_db;
DROP TABLE IF EXISTS employee_enc_grouped;
CREATE TABLE employee_enc_grouped (
  id INT,
  name VARCHAR(50),
  department VARCHAR(32),
  salary_enc_bfv LONGTEXT
);

INSERT INTO employee_enc_grouped
SELECT id, name, department, HERMES_ENC_SINGULAR_BFV(salary)
FROM employee_grouped;
EOF

echo -e "\n[3] Previewing ciphertext prefix (first 8 chars)..."
mysql -u $MYSQL_USER <<EOF
USE hpdic_db;
SELECT 
  id, 
  name, 
  department, 
  LEFT(salary_enc_bfv, 8) AS salary_enc_preview
FROM employee_enc_grouped;
EOF

echo -e "\n[4] Decrypting encrypted salaries using HERMES_DEC_SINGULAR_BFV..."
mysql -u $MYSQL_USER <<EOF
USE hpdic_db;
SELECT 
  id, 
  name, 
  department, 
  HERMES_DEC_SINGULAR_BFV(salary_enc_bfv) AS salary_plain
FROM employee_enc_grouped;
EOF

echo -e "\n[5] Performing homomorphic sum by department using HERMES_SUM_BFV..."
mysql -u $MYSQL_USER <<EOF
USE hpdic_db;
SELECT 
  department, 
  HERMES_SUM_BFV(salary_enc_bfv) AS total_salary
FROM employee_enc_grouped
GROUP BY department
ORDER BY department;
EOF

echo -e "\n[6] Adding encrypted months column (12 months/year)..."
mysql -u $MYSQL_USER <<EOF
USE hpdic_db;
ALTER TABLE employee_enc_grouped ADD COLUMN months_enc_bfv LONGTEXT;
UPDATE employee_enc_grouped 
SET months_enc_bfv = HERMES_ENC_SINGULAR_BFV(12);
EOF

echo -e "\n[7] Computing annual salary = salary × months (homomorphic mul)..."
mysql -u $MYSQL_USER <<EOF
USE hpdic_db;
SELECT 
  name, 
  HERMES_DEC_SINGULAR_BFV(HERMES_MUL_BFV(salary_enc_bfv, months_enc_bfv)) AS annual_salary
FROM employee_enc_grouped;
EOF

echo -e "\n[✓] Test completed successfully."
