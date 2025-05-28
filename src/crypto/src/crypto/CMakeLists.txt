# CMakeLists for crypto module

add_library(crypto
    context.cpp
    keygen.cpp
    encrypt.cpp
    decrypt.cpp
)

target_include_directories(crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Unit tests
add_executable(test_crypto
    test/test_context.cpp
    test/test_keygen.cpp
    test/test_encrypt.cpp
    test/test_decrypt.cpp
)

target_link_libraries(test_crypto PRIVATE crypto)
