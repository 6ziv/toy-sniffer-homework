cmake_minimum_required(VERSION 3.20)
project(npcap-sdk CXX)
set(CMAKE_CXX_STANDARD 20)
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/Lib/Packet.lib)
file(DOWNLOAD
    "https://npcap.com/dist/npcap-sdk-1.12.zip"
    ${CMAKE_CURRENT_BINARY_DIR}/npcap-sdk-1.12.zip
    SHOW_PROGRESS
    EXPECTED_MD5 e898fb8d2a4aa487a3e0ec06c410dfba)
execute_process(
    COMMAND ${CMAKE_COMMAND} -E tar xvf ${CMAKE_CURRENT_BINARY_DIR}/npcap-sdk-1.12.zip
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()
add_library(npcap-sdk INTERFACE)
if(CMAKE_SIZEOF_VOID_P  EQUAL 8)
    target_link_libraries(npcap-sdk
        INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/Lib/x64/Packet.lib
        INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/Lib/x64/wpcap.lib
        )
else()
    target_link_libraries(npcap-sdk
        INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/Lib/Packet.lib
        INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/Lib/wpcap.lib
        )
endif()
target_include_directories(npcap-sdk INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/Include)
#https://npcap.com/dist/npcap-sdk-1.12.zip
