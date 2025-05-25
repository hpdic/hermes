cmake_minimum_required(VERSION 3.10)
project(hermes_mysql_udf)

# ========== 依赖路径 ==========
# MySQL client headers
include_directories(/usr/include/mysql)

# OpenFHE headers
include_directories(/usr/local/include/openfhe) # for openfhe.h
include_directories(/usr/local/include/openfhe/core)
include_directories(/usr/local/include/openfhe/pke)
include_directories(/usr/local/include/openfhe/binfhe)

# OpenFHE lib
link_directories(/usr/local/lib)

# ========== 源码文件 ==========
file(GLOB UDF_SRC src/mysql/*.cpp)

# ========== 插件构建 ==========
add_library(hermes_udf SHARED ${UDF_SRC})

# ========== 链接库 ==========
find_library(MYSQLCLIENT_LIBRARY NAMES mysqlclient REQUIRED)

target_link_libraries(hermes_udf
    ${MYSQLCLIENT_LIBRARY}
    OPENFHEcore
    OPENFHEpke
    OPENFHEbinfhe
)
# ========== 插件名称 ==========
set_target_properties(hermes_udf PROPERTIES OUTPUT_NAME "hermes_udf")