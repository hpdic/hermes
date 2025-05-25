#!/bin/bash
# ============================================================
# HERMES UDF: Group-Aware Compile + Deploy + Encrypted SQL Test
# Author: Dr. Dongfang Zhao (dzhao@cs.washington.edu)
# Description: Group-by aware MySQL UDF homomorphic test.
# ============================================================

set -e

echo "[*] Restarting MySQL to clear UDF state..."
sudo systemctl restart mysql
sleep 1

MYSQL_USER="hpdic"
MYSQL_PASS="hpdic2023"
PLUGIN_NAME="libhermes_udf.so"

# === 编译并部署到 MySQL 插件目录 ===
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo cp -v ${PLUGIN_NAME} /usr/lib/mysql/plugin

# === 注册函数 + 创建表 + 加密 + 解密 + 分组聚合 ===
mysql -u $MYSQL_USER -p$MYSQL_PASS <<EOF
CREATE DATABASE IF NOT EXISTS hpdic_db;
USE hpdic_db;

-- 测试数据表：含部门字段
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

-- 注册加解密和聚合函数
DROP FUNCTION IF EXISTS HERMES_ENC_SINGULAR_BFV;
DROP FUNCTION IF EXISTS HERMES_DEC_SINGULAR_BFV;
DROP FUNCTION IF EXISTS HERMES_SUM_BFV;

CREATE FUNCTION HERMES_ENC_SINGULAR_BFV RETURNS STRING SONAME '${PLUGIN_NAME}';
CREATE FUNCTION HERMES_DEC_SINGULAR_BFV RETURNS INTEGER SONAME '${PLUGIN_NAME}';
CREATE AGGREGATE FUNCTION HERMES_SUM_BFV RETURNS INTEGER SONAME '${PLUGIN_NAME}';

-- 加密后存储
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
SELECT 
  id, 
  name, 
  department, 
  LEFT(salary_enc_bfv, 8) AS salary_enc_preview 
FROM employee_enc_grouped;

-- 解密验证
SELECT id, name, department, HERMES_DEC_SINGULAR_BFV(salary_enc_bfv) AS salary_plain
FROM employee_enc_grouped;

-- 分组聚合：部门工资总和
SELECT department, HERMES_SUM_BFV(salary_enc_bfv) AS total_salary
FROM employee_enc_grouped
GROUP BY department
ORDER BY department;
EOF

echo "[✓] Group-by 加密聚合测试完成"