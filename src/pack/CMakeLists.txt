# File: pack/CMakeLists.txt

# --------------------------
# Packing-based conversion UDF
# --------------------------
add_library(hermes_pack_convert_udf SHARED
    packing.cpp
    ../crypto/base64.cpp
    ../crypto/context.cpp
    ../crypto/encrypt.cpp
    ../crypto/keygen.cpp
    ../crypto/serialize.cpp
)

target_include_directories(hermes_pack_convert_udf PRIVATE
    ${OpenFHE_INCLUDE_DIRS}
    ${MySQL_INCLUDE_DIR}
    ${PROJECT_SOURCE_DIR}/src/crypto  # to access shared headers

)

target_link_libraries(hermes_pack_convert_udf
    ${OpenFHE_LIBRARIES}
    ${MySQL_LIBRARIES}
    crypto
)

set_target_properties(hermes_pack_convert_udf PROPERTIES
    OUTPUT_NAME "hermes_pack_convert"
)

# --------------------------
# Packed sum UDFs (group + global)
# --------------------------
add_library(hermes_packsum_udf SHARED
    packsum.cpp
    ../crypto/base64.cpp
    ../crypto/context.cpp
    ../crypto/encrypt.cpp
    ../crypto/keygen.cpp
    ../crypto/serialize.cpp
)

target_include_directories(hermes_packsum_udf PRIVATE
    ${OpenFHE_INCLUDE_DIRS}
    ${MySQL_INCLUDE_DIR}
    ${PROJECT_SOURCE_DIR}/src/crypto
)

target_link_libraries(hermes_packsum_udf
    ${OpenFHE_LIBRARIES}
    ${MySQL_LIBRARIES}
    crypto
)

set_target_properties(hermes_packsum_udf PROPERTIES
    OUTPUT_NAME "hermes_packsum"
)

# --------------------------
# Packed slot-wise update UDFs (add/remove)
# --------------------------
add_library(hermes_packupdate_udf SHARED
    packupdate.cpp
    ../crypto/base64.cpp
    ../crypto/context.cpp
    ../crypto/encrypt.cpp
    ../crypto/keygen.cpp
    ../crypto/serialize.cpp
)

target_include_directories(hermes_packupdate_udf PRIVATE
    ${OpenFHE_INCLUDE_DIRS}
    ${MySQL_INCLUDE_DIR}
    ${PROJECT_SOURCE_DIR}/src  # enables #include "crypto/xxx.hpp"
)

target_link_libraries(hermes_packupdate_udf
    ${OpenFHE_LIBRARIES}
    ${MySQL_LIBRARIES}
    crypto
)

set_target_properties(hermes_packupdate_udf PROPERTIES
    OUTPUT_NAME "hermes_packupdate"
)