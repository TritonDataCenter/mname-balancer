#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright (c) 2018, Joyent, Inc.
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
		#-I$(TOP)/deps/smartos/include \

OBJ_DIR =	obj

$(PROG): $(OBJS:%=$(OBJ_DIR)/%) $(DEPS_LIBS:%=$(OBJ_DIR)/%)
	gcc $(CFLAGS) -o $@ $(OBJS:%=$(OBJ_DIR)/%) $(OBJ_DIR)/bunyan_provider.o $(LIBS)
	/opt/ctf/bin/ctfconvert -o $@ $@

$(OBJ_DIR):
	mkdir -p $@

$(OBJ_DIR)/%.o: %.c $(HEADERS) | $(OBJ_DIR)
	gcc -c $(CFLAGS) -o $@ $<

$(OBJ_DIR)/%.o: deps/libcloop/src/%.c | $(OBJ_DIR)
	gcc -c $(CFLAGS) -o $@ $<

#%.o: deps/smartos/src/%.c
#	gcc -c $(CFLAGS) -o $@ $<

$(OBJ_DIR)/illumos_list.a: | deps/illumos-list/.git $(OBJ_DIR)
	cd deps/illumos-list && $(MAKE) BUILD_DIR=$(TOP)/$(OBJ_DIR) \
	    EXTRA_CFLAGS=-pthread

$(OBJ_DIR)/illumos_bunyan.a: | deps/illumos-bunyan/.git $(OBJ_DIR)
	cd deps/illumos-bunyan && $(MAKE) BUILD_DIR=$(TOP)/$(OBJ_DIR) \
	    EXTRA_CFLAGS=-pthread

$(OBJ_DIR)/libcbuf.a: | deps/libcbuf/.git $(OBJ_DIR)
	cd deps/libcbuf && $(MAKE) OBJ_DIR=$(TOP)/$(OBJ_DIR) \
	    DESTDIR=$(TOP)/$(OBJ_DIR) EXTRA_CFLAGS=-pthread

deps/%/.git:
	git submodule update --init --recursive

clean:
	rm -f $(PROG)
	rm -f $(OBJ_DIR)/*.o

clobber: clean
	cd deps/illumos-list && $(MAKE) clean
	rm -rf $(OBJ_DIR)
