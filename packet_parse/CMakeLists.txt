cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(packet_parse)
set(CMAKE_CXX_STANDARD 14)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

aux_source_directory(. DIR_LIB_SRCS)

add_library (${PROJECT_NAME} ${DIR_LIB_SRCS})

target_link_libraries(${PROJECT_NAME} 
    libPcap++.a 
    libPacket++.a 
    libCommon++.a
)

target_link_libraries(${PROJECT_NAME}
    pcap
    pthread
)

find_path(/opt/scripts json.hpp)
target_include_directories(${PROJECT_NAME} PRIVATE /opt/scripts)
