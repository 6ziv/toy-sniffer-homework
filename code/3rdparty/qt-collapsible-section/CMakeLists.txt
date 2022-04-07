cmake_minimum_required(VERSION 3.20)
project(qt_collapsible_section CXX)
set(CMAKE_CXX_STANDARD 20)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
find_package(QT NAMES Qt6 Qt5 COMPONENTS Core Widgets Gui REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Core Widgets Gui REQUIRED)
if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_library(qt_collapsible_section
        STATIC
        MANUAL_FINALIZATION
        ${CMAKE_CURRENT_SOURCE_DIR}/Section.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/Section.h
    )
else()
    add_library(qt_collapsible_section ${CMAKE_CURRENT_SOURCE_DIR}/Section.cpp)
endif()
target_include_directories(qt_collapsible_section SYSTEM PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(qt_collapsible_section PRIVATE Qt${QT_VERSION_MAJOR}::Core Qt${QT_VERSION_MAJOR}::Widgets)
if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_target(QHexView)
endif()
