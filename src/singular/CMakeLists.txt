cmake_minimum_required(VERSION 3.10)
project(hermes_singular_udf)

# Build the singular UDF plugin as a shared library
add_library(hermes_singular_udf SHARED
    udf.cpp
    ../crypto/base64.cpp
    ../crypto/context.cpp
    ../crypto/encrypt.cpp
    ../crypto/keygen.cpp
    ../crypto/serialize.cpp)

# Include directories
target_include_directories(hermes_singular_udf PRIVATE
    /usr/include/mysql
    /usr/local/include/openfhe
    /usr/local/include/openfhe/core
    /usr/local/include/openfhe/pke
    /usr/local/include/openfhe/binfhe
    ${CMAKE_CURRENT_SOURCE_DIR}/../crypto
)

# Link libraries
find_library(MYSQLCLIENT_LIBRARY NAMES mysqlclient REQUIRED)

target_link_libraries(hermes_singular_udf
    ${MYSQLCLIENT_LIBRARY}
    OPENFHEcore
    OPENFHEpke
    OPENFHEbinfhe
    crypto
)

# Set output name
set_target_properties(hermes_singular_udf PROPERTIES
    OUTPUT_NAME "hermes_singular_udf"
)