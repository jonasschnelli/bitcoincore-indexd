# Copyright (c) 2018 Jonas Schnelli
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

ACLOCAL_AMFLAGS = -I build-aux/m4
SUBDIRS = src
.PHONY: deploy FORCE

export PYTHONPATH

BITCOINCOREINDEXD_BIN=$(top_builddir)/src/$(BITCOINCOREINDEXD_DAEMON_NAME)$(EXEEXT)

empty :=
space := $(empty) $(empty)

$(BITCOINCOREINDEXD_BIN): FORCE
	$(MAKE) -C src $(@F)

dist_noinst_SCRIPTS = autogen.sh

CLEANFILES = $(OSX_DMG) $(BITCOIN_WIN_INSTALLER)
