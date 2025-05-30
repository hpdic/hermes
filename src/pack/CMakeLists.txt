# File: pack/CMakeLists.txt

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