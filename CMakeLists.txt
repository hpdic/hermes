# ============================================================
# CMakeLists.txt — Build Configuration for Hermes UDF Plugin
# Author: Dr. Dongfang Zhao (dzhao@cs.washington.edu)
# Last Updated: 2025-05-26
#
# This CMake build script compiles the Hermes MySQL UDF plugin,
# which enables encrypted SQL computation using OpenFHE (BFV scheme).
#
# Features:
# - Automatically includes all UDF source files from src/mysql/
# - Links against OpenFHE (core, pke, binfhe) and MySQL client libraries
# - Produces a dynamically loadable .so plugin for MySQL
#
# Requirements:
# - OpenFHE installed under /usr/local (default build location)
# - MySQL development headers and libmysqlclient available
#
# Usage:
#   $ mkdir build && cd build
#   $ cmake ..
#   $ make
#   $ sudo cp libhermes_udf.so /usr/lib/mysql/plugin/
#
# Note: If OpenFHE or MySQL is installed elsewhere, modify the include/link
# paths accordingly.
# ============================================================

cmake_minimum_required(VERSION 3.10)
project(hermes_mysql_udf)

# ========== Include Directories ==========
# MySQL client development headers
include_directories(/usr/include/mysql)

# OpenFHE headers (required for OpenFHE::CryptoContext and BFV APIs)
include_directories(/usr/local/include/openfhe)
include_directories(/usr/local/include/openfhe/core)
include_directories(/usr/local/include/openfhe/pke)
include_directories(/usr/local/include/openfhe/binfhe)

# ========== Library Search Path ==========
# Make sure the linker can find OpenFHE shared libraries
link_directories(/usr/local/lib)

# ========== Source Files ==========
# Automatically include all UDF source files under src/mysql/
file(GLOB UDF_SRC src/mysql/*.cpp)

# ========== Build Shared Plugin ==========
# Build the UDF plugin as a shared object for MySQL to load dynamically
add_library(hermes_udf SHARED ${UDF_SRC})

# ========== Link Libraries ==========
# Link against the MySQL client library and OpenFHE core modules
find_library(MYSQLCLIENT_LIBRARY NAMES mysqlclient REQUIRED)

target_link_libraries(hermes_udf
    ${MYSQLCLIENT_LIBRARY}
    OPENFHEcore
    OPENFHEpke
    OPENFHEbinfhe
)

# ========== Plugin Output Name ==========
# Output as libhermes_udf.so instead of default libhermes_mysql_udf.so
set_target_properties(hermes_udf PROPERTIES OUTPUT_NAME "hermes_udf")