find_package(GTest REQUIRED)
find_package(benchmark REQUIRED)
find_package(SafeheronCryptoSuites REQUIRED)

include_directories(../src
        ${SafeheronCryptoSuites_INCLUDE_DIRS}
        ${GTEST_INCLUDE_DIRS})
link_libraries(CryptoTSSRSA
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARY_DIRS}
        benchmark::benchmark
        pthread)

add_executable(pure-tss-rsa-test pure-tss-rsa-test.cpp)
add_test(NAME pure-tss-rsa-test COMMAND pure-tss-rsa-test)

add_executable(tss-rsa-test tss-rsa-test.cpp)
add_test(NAME tss-rsa-test COMMAND tss-rsa-test)

if (${ENABLE_BENCHMARK})
    add_executable(tss-rsa-benchmark-test tss-rsa-benchmark-test.cpp)
    add_test(NAME tss-rsa-benchmark-test COMMAND tss-rsa-benchmark-test)
endif()

