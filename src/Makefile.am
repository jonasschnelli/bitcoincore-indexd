# Copyright (c) 2018 Jonas Schnelli
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = univalue

AM_LDFLAGS = $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

APPLICATION_INCLUDES=-I$(builddir)
APPLICATION_INCLUDES += $(UNIVALUE_CFLAGS)


APPNAME=Application
APPNAME_LC=application

bin_PROGRAMS = $(APPNAME_LC)
EXTRA_LIBRARIES += libapplication.a

# application qt core #
QT_TS = \
  locale/$(APPNAME_LC)_en_GB.ts

QT_FORMS_UI = \
  forms/mainwindow.ui

QT_MOC_CPP = \
  moc_mainwindow.cpp

QT_QRC_CPP = qrc_$(APPNAME_LC).cpp
QT_QRC = $(APPNAME_LC).qrc
QT_QRC_LOCALE_CPP = qrc_$(APPNAME_LC)_locale.cpp
QT_QRC_LOCALE = $(APPNAME_LC)_locale.qrc

APPLICATION_QT_H = \
  mainwindow.h

RES_ICONS = 

APPLICATION_QT_CPP = \
  main.cpp \
  mainwindow.cpp

RES_IMAGES = 

APPLICATION_RC = res/$(APPNAME_LC)-res.rc

APPLICATION_QT_INCLUDES = -DQT_NO_KEYWORDS

libapplication_a_CPPFLAGS = $(AM_CPPFLAGS) $(APPLICATION_INCLUDES) $(APPLICATION_QT_INCLUDES) \
  $(QT_INCLUDES) $(QT_DBUS_INCLUDES)
libapplication_a_CXXFLAGS = $(AM_CXXFLAGS) $(QT_PIE_FLAGS)
libapplication_a_OBJCXXFLAGS = $(AM_OBJCXXFLAGS) $(QT_PIE_FLAGS)

libapplication_a_SOURCES = $(APPLICATION_QT_CPP) $(APPLICATION_QT_H) $(QT_FORMS_UI) \
  $(QT_QRC) $(QT_QRC_LOCALE) $(QT_TS) $(RES_ICONS) $(RES_IMAGES)

nodist_libapplication_a_SOURCES = $(QT_MOC_CPP) $(QT_MOC) \
  $(QT_QRC_CPP) $(QT_QRC_LOCALE_CPP)

# forms/foo.h -> forms/ui_foo.h
QT_FORMS_H=$(join $(dir $(QT_FORMS_UI)),$(addprefix ui_, $(notdir $(QT_FORMS_UI:.ui=.h))))

# Most files will depend on the forms and moc files as includes. Generate them
# before anything else.
$(QT_MOC): $(QT_FORMS_H)
$(libapplication_a_OBJECTS) $(application_OBJECTS) : | $(QT_MOC)

# application binary #
application_CPPFLAGS = $(AM_CPPFLAGS) $(APPLICATION_INCLUDES) $(APPLICATION_QT_INCLUDES) \
  $(QT_INCLUDES)
application_CXXFLAGS = $(AM_CXXFLAGS) $(QT_PIE_FLAGS)

application_SOURCES = main.cpp
if TARGET_WINDOWS
  application_SOURCES += $(APPLICATION_RC)
endif
application_LDADD = libapplication.a
application_LDADD += $(LIBUNIVALUE) $(QT_LIBS) $(QT_DBUS_LIBS)
application_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(QT_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)
application_LIBTOOLFLAGS = --tag CXX

#locale/foo.ts -> locale/foo.qm
QT_QM=$(QT_TS:.ts=.qm)

SECONDARY: $(QT_QM)

$(QT_QRC_LOCALE_CPP): $(QT_QRC_LOCALE) $(QT_QM)
	@test -f $(RCC)
	@cp -f $< $(@D)/temp_$(<F)
	$(AM_V_GEN) QT_SELECT=$(QT_SELECT) $(RCC) -name $(APPNAME_LC)_locale $(@D)/temp_$(<F) | \
	  $(SED) -e '/^\*\*.*Created:/d' -e '/^\*\*.*by:/d' > $@
	@rm $(@D)/temp_$(<F)

$(QT_QRC_CPP): $(QT_QRC) $(QT_FORMS_H) $(RES_ICONS) $(RES_IMAGES)
	@test -f $(RCC)
	$(AM_V_GEN) QT_SELECT=$(QT_SELECT) $(RCC) -name $(APPNAME_LC) $< | \
	  $(SED) -e '/^\*\*.*Created:/d' -e '/^\*\*.*by:/d' > $@
    
CLEAN_QT = $(nodist_libapplication_a_SOURCES) $(QT_QM) $(QT_FORMS_H)

CLEANFILES = $(CLEAN_QT)

application_clean: FORCE
	rm -f $(CLEAN_QT) libapplication.a $(libapplication_a_OBJECTS) $(application_OBJECTS) $(APPNAME_LC)$(EXEEXT) $(LIBAPPLICATION)

ui_%.h: %.ui
	@test -f $(UIC)
	@$(MKDIR_P) $(@D)
	$(AM_V_GEN) QT_SELECT=$(QT_SELECT) $(UIC) -o $@ $< || (echo "Error creating $@"; false)

%.moc: %.cpp
	$(AM_V_GEN) QT_SELECT=$(QT_SELECT) $(MOC) $(DEFAULT_INCLUDES) $(QT_INCLUDES) $(MOC_DEFS) $< | \
	  $(SED) -e '/^\*\*.*Created:/d' -e '/^\*\*.*by:/d' > $@

moc_%.cpp: %.h
	$(AM_V_GEN) QT_SELECT=$(QT_SELECT) $(MOC) $(DEFAULT_INCLUDES) $(QT_INCLUDES) $(MOC_DEFS) $< | \
	  $(SED) -e '/^\*\*.*Created:/d' -e '/^\*\*.*by:/d' > $@

%.qm: %.ts
	@test -f $(LRELEASE)
	@$(MKDIR_P) $(@D)
	$(AM_V_GEN) QT_SELECT=$(QT_SELECT) $(LRELEASE) -silent $< -qm $@
