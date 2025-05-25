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
#
# Assumes: Plugin is already compiled, registered, and MySQL is running.
# ============================================================

set -e

MYSQL_USER="hpdic"
MYSQL_PASS="hpdic2023"

echo "[*] Running encrypted SQL tests..."

mysql -u $MYSQL_USER -p$MYSQL_PASS <<EOF
-- Setup database and base table
CREATE DATABASE IF NOT EXISTS hpdic_db;
USE hpdic_db;

DROP TABLE IF EXISTS employee_grouped;
CREATE TABLE employee_grouped (
  id INT,
  name VARCHAR(50),
  department VARCHAR(32),
  salary INT
);

-- Insert test data
INSERT INTO employee_grouped VALUES
  (1, 'Alice', 'HR', 5200),
  (2, 'Bob',   'HR', 4800),
  (3, 'Carol', 'ENG', 6000),
  (4, 'Dave',  'ENG', 5900);

-- Encrypt salary column using Hermes
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

-- Preview ciphertext prefix
SELECT 
  id, 
  name, 
  department, 
  LEFT(salary_enc_bfv, 8) AS salary_enc_preview
FROM employee_enc_grouped;

-- Decrypt and validate salary
SELECT 
  id, 
  name, 
  department, 
  HERMES_DEC_SINGULAR_BFV(salary_enc_bfv) AS salary_plain
FROM employee_enc_grouped;

-- Homomorphic SUM by department
SELECT 
  department, 
  HERMES_SUM_BFV(salary_enc_bfv) AS total_salary
FROM employee_enc_grouped
GROUP BY department
ORDER BY department;
EOF

echo "[✓] Test completed successfully."