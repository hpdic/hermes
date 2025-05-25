cmake_minimum_required(VERSION 3.10)
project(hermes_mysql_udf)

find_package(OpenFHE REQUIRED)
include_directories(${OpenFHE_INCLUDE_DIRS})

file(GLOB UDF_SRC src/mysql/*.cpp)
add_library(hermes_udf SHARED ${UDF_SRC})
target_link_libraries(hermes_udf ${OpenFHE_LIBRARIES})
set_target_properties(hermes_udf PROPERTIES OUTPUT_NAME "libhermes_udf")
