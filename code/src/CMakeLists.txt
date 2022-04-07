cmake_minimum_required(VERSION 3.5)

project(MySniffer VERSION 0.1 LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(/DWIN32_LEAN_AND_MEAN /DNOMINMAX)

find_package(QT NAMES Qt6 Qt5 COMPONENTS Widgets LinguistTools REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Widgets LinguistTools REQUIRED)

set(PROJECT_SOURCES
    adapterselector.cpp
    listhelper.cpp
    main.cpp
    mainwindow.cpp
    protocols.cpp
    sniffthread.cpp
    statplot.cpp
    statthread.cpp
    adapterselector.h
    addresstranslator.hpp
    endian.hpp
    fieldnames.hpp
    filter.hpp
    filterhelper.hpp
    headerformats.hpp
    listhelper.h
    mainwindow.h
    packetinterpreter.hpp
    protocols.h
    sniffthread.h
    statplot.h
    statthread.h
    tracer.hpp
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt6_add_executable(MySniffer
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
    qt6_add_translations(MySniffer TS_FILES MySniffer_zh_CN.ts)
else()
    add_executable(MySniffer
        ${PROJECT_SOURCES}
    )
    qt5_add_translation(MySniffer MySni)
endif()

target_link_libraries(MySniffer PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)
target_link_libraries(MySniffer PUBLIC
    boost aixlog QHexEdit QHexView qt_collapsible_section span-ext
    )
target_link_libraries(MySniffer PRIVATE npcap-sdk)
set_target_properties(MySniffer PROPERTIES
    MACOSX_BUNDLE_GUI_IDENTIFIER my.example.com
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)
target_link_libraries(MySniffer PRIVATE Iphlpapi.lib)
if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(MySniffer)
endif()
