#-----------------------------------------------------------------------------------------------------------------------------------
#
# PROJECT:            Engineering Workshop Tracker (engineeringShop)
# FILE:								plugin_salesTax_AU.pro
# SUBSYSTEM:          Project File
# LANGUAGE:						C++
# TARGET OS:          LINUX
# LIBRARY DEPENDANCE:	None.
# NAMESPACE:          N/A
# AUTHOR:							Gavin Blakeman.
# LICENSE:            GPLv2
#
#                     Copyright 2022 Gavin Blakeman.
#
# OVERVIEW:						Project file for compiling the project
#
# HISTORY:            2022-07-05/GGB - File Created
#
#-----------------------------------------------------------------------------------------------------------------------------------

TARGET = plugin_bcrypt

DESTDIR = ../engineeringShop/plugins/hashSchemes

TEMPLATE = lib

QT += core
QT -= gui

CONFIG += cmdline
CONFIG += plugin no_plugin_name_prefix
CONFIG -= app_bundle
CONFIG += object_parallel_to_source

QMAKE_CXXFLAGS += -std=c++20
QMAKE_LFLAGS += -Wl,--version-script=$${PWD}/pluginPassword.version
DEFINES += BOOST_THREAD_USE_LIB QT_GUI_LIB QT_CORE_LIB

DEFINES += SW_VERSION=\\\"$$system(git describe --always --abbrev=0)\\\"


#OBJECTS_DIR = "objects"

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

INCLUDEPATH +=  \
    "../engineeringShop" \
    "../GCL" \
    "../MCL" \
    "../PCL" \
    "../SCL" \
    "/usr/local/lib" \

SOURCES += \
  source/plugin_hashScheme_bcrypt.cpp

HEADERS +=

LIBS += -lcrypt

