#-------------------------------------------------
#
# Project created by QtCreator 2016-07-05T15:25:16
#
#-------------------------------------------------

QT       += testlib
QT       -= gui

TARGET = tst_testskunwind
CONFIG   += console
CONFIG   -= app_bundle
CONFIG   += c++14

TEMPLATE = app

SOURCES += tst_testskunwind.cpp
DEFINES += SRCDIR=\\\"$$PWD/\\\"

unix:!macx: LIBS += -L$$OUT_PWD/../libkunwind/ -llibkunwind

INCLUDEPATH += $$PWD/../libkunwind
DEPENDPATH += $$PWD/../libkunwind

INCLUDEPATH += $$PWD/../include
