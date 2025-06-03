#!/bin/bash
set -e

echo "[*] Converting raw data to CSV format..."

# Default group size
GROUP_SIZE=${GROUP_SIZE:-8192}
TMP_DIR="./tmp"
mkdir -p "$TMP_DIR"

convert() {
    local input=$1
    local output=$2
    local colname=$3

    echo "[*] Processing $input → $output"

    awk -v gsize="$GROUP_SIZE" -v colname="$colname" '
    BEGIN {
        OFS=",";
        print "id", "group_id", colname;
    }
    {
        gsub(/,/, "", $0);           # remove commas
        gsub(/[^0-9.\-]/, "", $0);   # remove non-numeric
        if ($0 ~ /^[0-9.\-]+$/) {
            val = int($0 + 0.5);     # round float to int
            id = ++count;
            gid = int((id - 1) / gsize);
            print id, gid, val;
        }
    }
    ' "$input" > "$output"
}

convert "${TMP_DIR}/bitcoin" "$TMP_DIR/bitcoin.csv" "btc_volume"
convert "${TMP_DIR}/covid19" "$TMP_DIR/covid19.csv" "covid_metric"
convert "${TMP_DIR}/hg38" "$TMP_DIR/hg38.csv" "gene_metric"

echo "[✓] CSV files created under $TMP_DIR/"