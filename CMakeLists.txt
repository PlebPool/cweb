cmake_minimum_required(VERSION 3.31)
project(cweb C)

set(CMAKE_C_STANDARD 99)

include_directories(include)

add_library(cweb STATIC library.c src/server.c src/wsocket.c)

target_include_directories(cweb PUBLIC include)

find_package(OpenSSL REQUIRED)

target_link_libraries(cweb PRIVATE cstring cthread OpenSSL::SSL OpenSSL::Crypto)