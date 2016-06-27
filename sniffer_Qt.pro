#-------------------------------------------------
#
# Project created by QtCreator 2016-06-14T21:12:49
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = sniffer_Qt
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    mythread.cpp

HEADERS  += mainwindow.h \
    mythread.h \
    header.h

FORMS    += mainwindow.ui
#LIBS+=Packet.lib wpcap.lib
LIBS += -L/usr/local/lib -lpcap
