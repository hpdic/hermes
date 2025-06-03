#!/bin/bash
set -e

export MYSQL_PWD="hpdic2023"

# Configuration
MYSQL_USER="hpdic"
MYSQL_DB="hermes_apps"
TMP_DIR="./tmp"
MYSQL_CMD="mysql --local-infile=1 -u $MYSQL_USER -D $MYSQL_DB"

echo "[*] Creating database (if not exists)..."
$MYSQL_CMD -e "CREATE DATABASE IF NOT EXISTS $MYSQL_DB;"

# Drop + create + import a table from CSV
import_table() {
    local name=$1
    local file=$2
    echo "[*] Importing $name from $file..."

    $MYSQL_CMD <<EOF
DROP TABLE IF EXISTS $name;
CREATE TABLE $name (
    id INT PRIMARY KEY,
    group_id INT,
    value INT
);
LOAD DATA LOCAL INFILE '$file'
INTO TABLE $name
FIELDS TERMINATED BY ','
IGNORE 1 LINES
(id, group_id, value);
EOF

    $MYSQL_CMD -e "SELECT COUNT(*) AS row_count FROM $name;"
}

import_table "tbl_bitcoin" "$TMP_DIR/bitcoin.csv"
import_table "tbl_covid19" "$TMP_DIR/covid19.csv"
import_table "tbl_hg38" "$TMP_DIR/hg38.csv"

echo "[✓] All tables imported into database '$MYSQL_DB'"