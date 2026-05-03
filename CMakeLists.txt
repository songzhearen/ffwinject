cmake_minimum_required(VERSION 3.20)
project(ffwinject LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(ffwinject WIN32 src/main.cpp)
target_link_options(ffwinject PRIVATE -municode -static)
