# File: pack/CMakeLists.txt

add_library(hermes_pack_convert_udf SHARED
    packing.cpp
)

target_include_directories(hermes_pack_convert_udf PRIVATE
    ${OpenFHE_INCLUDE_DIRS}
    ${MySQL_INCLUDE_DIR}
    ../src/crypto  # to access shared headers

)

target_link_libraries(hermes_pack_convert_udf
    ${OpenFHE_LIBRARIES}
    ${MySQL_LIBRARIES}
)

set_target_properties(hermes_pack_convert_udf PROPERTIES
    OUTPUT_NAME "hermes_pack_convert"
)