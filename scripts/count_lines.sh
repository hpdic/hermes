#!/bin/bash

echo "===== Hermes Code Line Count Breakdown ====="
ROOT="."
EXCLUDE_DIRS="build|.vscode|external|patch|tmp"

count() {
  find "$ROOT" -type f \
    | grep -vE "/($EXCLUDE_DIRS)/" \
    | grep "$1" \
    | xargs cat 2>/dev/null | wc -l
}

cpp_lines=$(find $ROOT -type f | grep -vE "/($EXCLUDE_DIRS)/" | grep -E '\.cpp$|\.cc$|\.cxx$|\.hpp$|\.h$|\.hh$|\.hxx$' | xargs cat 2>/dev/null | wc -l)
py_lines=$(count '\.py$')
cmake_lines=$(find $ROOT -type f | grep -vE "/($EXCLUDE_DIRS)/" | grep -E 'CMakeLists\.txt$|\.cmake$' | xargs cat 2>/dev/null | wc -l)
sh_lines=$(count '\.sh$')
md_lines=$(count '\.md$')

total=$((cpp_lines + py_lines + cmake_lines + sh_lines + md_lines))

printf "\n%-20s: %6d lines\n" "C++ (src + header)" $cpp_lines
printf "%-20s: %6d lines\n" "Python" $py_lines
printf "%-20s: %6d lines\n" "CMake" $cmake_lines
printf "%-20s: %6d lines\n" "Shell Script" $sh_lines
printf "%-20s: %6d lines\n" "Markdown" $md_lines
echo "--------------------------------------------"
printf "%-20s: %6d lines\n" "Total" $total