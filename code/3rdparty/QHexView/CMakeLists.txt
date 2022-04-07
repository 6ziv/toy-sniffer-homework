cmake_minimum_required(VERSION 3.20)
project(QHexView CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
find_package(QT NAMES Qt6 Qt5 COMPONENTS Core Widgets Gui REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Core Widgets Gui REQUIRED)
if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_library(QHexView
        STATIC
        MANUAL_FINALIZATION
        ${CMAKE_CURRENT_SOURCE_DIR}/QHexView/src/QHexView.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/QHexView/include/QHexView.h
    )
else()
    add_library(QHexView
               ${CMAKE_CURRENT_SOURCE_DIR}/QHexView/src/QHexView.cpp
               ${CMAKE_CURRENT_SOURCE_DIR}/QHexView/include/QHexView.h
    )
endif()
target_include_directories(QHexView SYSTEM PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/QHexView/include)
target_link_libraries(QHexView PRIVATE Qt${QT_VERSION_MAJOR}::Core Qt${QT_VERSION_MAJOR}::Widgets)
if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_target(QHexView)
endif()
