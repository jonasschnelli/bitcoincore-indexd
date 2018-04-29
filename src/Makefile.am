# Copyright (c) 2018 Jonas Schnelli
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = univalue libbtc

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

LIBBTC = libbtc/libbtc.la
$(LIBBTC): $(wildcard libbtc/src/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

bin_PROGRAMS = bitcoincore-indexd

BITCOINCORE_INDEXD_H = \
    btcnode.h \
    utils.h \
    dbinterface.h \
    databaselmdb.h

DATABASE_LMDB_SOURCES = \
    databaselmdb.cpp
    
BITCOINCORE_INDEXD_SOURCES = \
    btcnode.cpp \
    main.cpp \
    utils.cpp \
    $(DATABASE_LMDB_SOURCES) \
    $(BITCOINCORE_INDEXD_H)

# application binary #
bitcoincore_indexd_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir) $(UNIVALUE_CFLAGS) $(LIBUNIVALUE_CFLAGS) $(LIBBTC_CFLAGS)
bitcoincore_indexd_CXXFLAGS = $(AM_CXXFLAGS)
bitcoincore_indexd_SOURCES = $(BITCOINCORE_INDEXD_SOURCES)
bitcoincore_indexd_LDADD = $(LIBUNIVALUE) $(LIBBTC) $(LMDB_LIBS)
bitcoincore_indexd_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)
bitcoincore_indexd_LIBTOOLFLAGS = --tag CXX
