#-------------------------------------------------
#
# Project created by QtCreator 2016-07-05T15:23:55
#
#-------------------------------------------------

QT += core
QT -= gui

TARGET = libkunwind
TEMPLATE = lib

DEFINES += LIBKUNWIND_LIBRARY

INCLUDEPATH += $$PWD/../include

SOURCES += libkunwind.cpp

HEADERS += libkunwind.h\
        libkunwind_global.h
HEADERS += ../include/kunwind.h

unix {
    target.path = /usr/lib
    INSTALLS += target
}
