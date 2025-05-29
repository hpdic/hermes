# CMakeLists.txt for the 'crypto' module in HERMES

# -----------------------
# Static Library: crypto
# -----------------------
add_library(crypto
    context.cpp
    keygen.cpp
    encrypt.cpp
    decrypt.cpp
)

# Make headers in this directory available to users of the 'crypto' target
target_include_directories(crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    /usr/local/include/openfhe
    /usr/local/include/openfhe/core
    /usr/local/include/openfhe/pke
    /usr/local/include/openfhe/binfhe
)

# Link against OpenFHE libraries (adjust as needed)
target_link_libraries(crypto PUBLIC
    /usr/local/lib/libOPENFHEpke.so
    /usr/local/lib/libOPENFHEcore.so
    /usr/local/lib/libOPENFHEbinfhe.so
)

# -----------------------
# Unit Tests for crypto
# -----------------------
# Each test must be a separate executable (each has its own main())
add_executable(test_keygen test/test_keygen.cpp)
target_link_libraries(test_keygen PRIVATE crypto)

add_executable(test_encrypt test/test_encrypt.cpp)
target_link_libraries(test_encrypt PRIVATE crypto)

add_executable(test_decrypt test/test_decrypt.cpp)
target_link_libraries(test_decrypt PRIVATE crypto)

add_executable(test_eval test/test_eval.cpp)
target_link_libraries(test_eval PRIVATE crypto)

# Optionally, add common include path for tests
target_include_directories(test_keygen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/test)
target_include_directories(test_encrypt PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/test)
target_include_directories(test_decrypt PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/test)
target_include_directories(test_eval PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/test)