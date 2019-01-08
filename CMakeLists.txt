cmake_minimum_required(VERSION 3.13)
project(cursefinal)

set(CMAKE_CXX_STANDARD 14)

#include (FindPCAP.cmake)
#include_directories("/home/ellioterexet/PCAP/libpcap-1.9.0")

SET(CMAKE_MODULE_PATH "/home/ellioterexet/CLionProjects/cursefinal/")
find_package(PCAP)

set(SOURCE_FILES main.cpp)
add_executable(mycurse ${SOURCE_FILES})

target_link_libraries(mycurse ${PCAP_LIBRARY})