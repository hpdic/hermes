# File: src/tools/CMakeLists.txt

add_executable(gen_keys
  gen_keys.cpp
  ../crypto/context.cpp
  ../crypto/keygen.cpp
  ../crypto/serialize.cpp     
)

target_include_directories(gen_keys PRIVATE
  ${PROJECT_SOURCE_DIR}/src/crypto
  /usr/local/include/openfhe
  /usr/local/include/openfhe/core
  /usr/local/include/openfhe/pke
  /usr/local/include/openfhe/binfhe
)

target_link_libraries(gen_keys
  OPENFHEcore
  OPENFHEpke
)

set_target_properties(gen_keys PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})