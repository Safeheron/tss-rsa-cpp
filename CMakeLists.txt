cmake_minimum_required(VERSION 3.10)

project("CryptoTSSRSA" VERSION 1.0.1)

set(CMAKE_CXX_STANDARD 11)
#SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")

add_subdirectory(src)

option(ENABLE_TESTS "Enable tests" OFF)
option(ENABLE_BENCHMARK "Enable benchmark" OFF)
if (${ENABLE_TESTS})
    enable_testing()
    include_directories(/usr/local/include)
    link_directories(/usr/local/lib)
    add_subdirectory(test)
endif()

include("cmake/setup_installation.cmake")