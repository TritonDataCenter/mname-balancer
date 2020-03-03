#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright (c) 2020, Joyent, Inc.
#

TOP =		$(PWD)


PROG =		bbal

OBJS =		main.o \
		cloop.o \
		cserver.o \
		tcp_proxy.o \
		udp_proxy.o \
		backend.o \
		remotes.o \
		timeouts.o

HEADERS =	bbal.h

DEPS_LIBS =	illumos_list.a \
		libcbuf.a \
		illumos_bunyan.a

LIBS =		$(DEPS_LIBS:%=$(OBJ_DIR)/%) -lnsl -lsocket -lumem -lavl -lnvpair

INCS =		$(TOP)/deps/illumos-list/include \
		$(TOP)/deps/libcbuf/include \
		$(TOP)/deps/libcloop/include \
		$(TOP)/deps/illumos-bunyan/include

CFLAGS =	-Wall -Wextra -Werror \
		-Wno-unused-parameter \
		-std=c99 -D__EXTENSIONS__ -pthread \
		-O0 -gdwarf-2 \
		-fno-inline-small-functions \
		$(INCS:%=-I%)

DEPS_CFLAGS +=	-pthread

OBJ_DIR =	$(TOP)/obj

#
# This repo is typically built via binder, which will set CTFCONVERT
# appropriately as an override.
#
CTFCONVERT =	/bin/true
CC =		gcc
GIT =		git

#
# Regrettably, we need to be able to build this software on systems prior to
# the introduction of the endian(3C) suite of functions.  This check is truly
# awful, and if this software is to be cross-compiled (e.g., using --sysroot)
# it will absolutely need to be changed.
#
ifeq (,$(wildcard /usr/include/endian.h))
DEPS_CFLAGS +=	-DLIBCBUF_NO_ENDIAN_H
endif

#
# Work around for "values.c is missing debug info" on older systems.
#
CTFFLAGS = -m

$(PROG): $(OBJS:%=$(OBJ_DIR)/%) $(DEPS_LIBS:%=$(OBJ_DIR)/%)
	$(CC) $(CFLAGS) -o $@ $(OBJS:%=$(OBJ_DIR)/%) \
	    $(OBJ_DIR)/bunyan_provider.o $(LIBS)
	$(CTFCONVERT) $(CTFFLAGS) $@

$(OBJ_DIR):
	mkdir -p $@

$(OBJ_DIR)/%.o: %.c $(HEADERS) | deps/libcbuf/.git $(OBJ_DIR)
	$(CC) -c $(CFLAGS) -o $@ $<

$(OBJ_DIR)/%.o: deps/libcloop/src/%.c | $(OBJ_DIR)
	$(CC) -c $(CFLAGS) -o $@ $<

$(OBJ_DIR)/illumos_list.a: | deps/illumos-list/.git $(OBJ_DIR)
	cd deps/illumos-list && $(MAKE) BUILD_DIR=$(OBJ_DIR) \
	    EXTRA_CFLAGS='$(DEPS_CFLAGS)'

$(OBJ_DIR)/illumos_bunyan.a: | deps/illumos-bunyan/.git $(OBJ_DIR)
	cd deps/illumos-bunyan && $(MAKE) BUILD_DIR=$(OBJ_DIR) \
	    EXTRA_CFLAGS='$(DEPS_CFLAGS)'

$(OBJ_DIR)/libcbuf.a: | deps/libcbuf/.git $(OBJ_DIR)
	cd deps/libcbuf && $(MAKE) OBJ_DIR=$(OBJ_DIR) \
	    DESTDIR=$(OBJ_DIR) EXTRA_CFLAGS='$(DEPS_CFLAGS)'

deps/%/.git:
	$(GIT) submodule update --init --recursive

clean:
	rm -f $(PROG)
	rm -f $(OBJ_DIR)/*.o

clobber: clean
	cd deps/illumos-list && $(MAKE) clean
	rm -rf $(OBJ_DIR)
