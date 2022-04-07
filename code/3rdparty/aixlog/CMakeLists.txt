cmake_minimum_required(VERSION 3.20)
project(aixlog CXX)

set(CMAKE_CXX_STANDARD 20)
add_library(aixlog INTERFACE)

target_include_directories(aixlog SYSTEM INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/aixlog/include)
