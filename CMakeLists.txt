cmake_minimum_required(VERSION 3.31)
project(cweb C)

set(CMAKE_C_STANDARD 99)

add_library(cweb STATIC library.c
        src/server.c
        include/server.h)
