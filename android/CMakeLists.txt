cmake_minimum_required(VERSION 3.4.1)
project(CryptoLib)

set (CMAKE_VERBOSE_MAKEFILE ON)
set (CMAKE_CXX_STANDARD 14)

add_library(react-native-crypto-lib            SHARED
            ../cpp/react-native-crypto-lib.cpp
            cpp-adapter.cpp
)

# Specifies a path to native header files.
include_directories(
            ../cpp
)
