QT       += core gui charts
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets
CONFIG += c++2a
# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0
include(QHexEdit/QHexEdit.pri)
SOURCES += \
    adapterselector.cpp \
    listhelper.cpp \
    main.cpp \
    mainwindow.cpp \
    protocols.cpp \
    qt-collapsible-section/Section.cpp \
    sniffthread.cpp \
    statplot.cpp \
    statthread.cpp \
    QHexView/src/QHexView.cpp
HEADERS += \
    adapterselector.h \
    addresstranslator.hpp \
    endian.hpp \
    fieldnames.hpp \
    filter.hpp \
    filterhelper.hpp \
    headerformats.hpp \
    listhelper.h \
    mainwindow.h \
    packetinterpreter.hpp \
    protocols.h \
    qt-collapsible-section/Section.h \
    sniffthread.h \
    statplot.h \
    statthread.h \
    QHexView/include/QHexView.h \
    tracer.hpp
DEFINES += WIN32_LEAN_AND_MEAN NOMINMAX
QMAKE_LFLAGS_WINDOWS += "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""

TRANSLATIONS += \
    MySniffer_zh_CN.ts
CONFIG += lrelease
CONFIG += embed_translations
INCLUDEPATH += E:\npcap-sdk-1.12\Include
INCLUDEPATH += C:\boost_1_78_0
INCLUDEPATH += D:\aixlog-1.5.0\include
INCLUDEPATH += QHexView/include
INCLUDEPATH += span_ext/include
LIBPATH += E:\npcap-sdk-1.12\Lib\x64
LIBS += Packet.lib wpcap.lib
LIBS += Iphlpapi.lib
# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
