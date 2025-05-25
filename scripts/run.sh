#!/bin/bash
# ============================================================
# test.sh — Run Encrypted SQL Tests via Hermes UDF Plugin
# Author: Dr. Dongfang Zhao (dzhao@cs.washington.edu)
# Last Updated: 2025-05-26
#
# This script tests the Hermes MySQL UDFs by:
# - Creating sample employee data
# - Encrypting salaries with BFV
# - Verifying decryption correctness
# - Running homomorphic aggregation via GROUP BY
# - Performing ciphertext × ciphertext multiplication (salary × months)
#
# Assumes: Plugin is already compiled, registered, and MySQL is running.
# ============================================================

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

echo -e "\n[8] Adding plaintext bonus_months column (1–2 months)..."
mysql -u $MYSQL_USER <<EOF
USE hpdic_db;
ALTER TABLE employee_enc_grouped ADD COLUMN bonus_months INT;
UPDATE employee_enc_grouped
SET bonus_months = FLOOR(1 + RAND() * 2);  -- random 1 or 2
EOF

echo -e "\n[9] Computing bonus salary = salary × bonus_months (scalar mul)..."
mysql -u $MYSQL_USER <<EOF
USE hpdic_db;
SELECT 
  name,
  bonus_months,
  HERMES_DEC_SINGULAR_BFV(
    HERMES_MUL_SCALAR_BFV(salary_enc_bfv, bonus_months)
  ) AS bonus_salary
FROM employee_enc_grouped;
EOF

echo -e "\n[✓] Test completed successfully."
