

TOP =		$(PWD)


PROG =		bbal

OBJS =		main.o \
		cloop.o \
		cserver.o

DEPS_LIBS =	illumos_list.a \
		libcbuf.a

LIBS =		$(DEPS_LIBS:%=$(OBJ_DIR)/%) -lnsl -lsocket -lumem -lavl

INCS =		$(TOP)/deps/illumos-list/include \
		$(TOP)/deps/libcbuf/include \
		$(TOP)/deps/libcloop/include

CFLAGS =	-Wall -Wextra -Werror \
		-Wno-unused-parameter \
		-std=c99 -D__EXTENSIONS__ \
		-O0 -gdwarf-2 \
		$(INCS:%=-I%)
		#-I$(TOP)/deps/smartos/include \

OBJ_DIR =	obj

$(PROG): $(OBJS:%=$(OBJ_DIR)/%) $(DEPS_LIBS:%=$(OBJ_DIR)/%)
	gcc $(CFLAGS) -o $@ $(OBJS:%=$(OBJ_DIR)/%) $(LIBS)
	/opt/ctf/bin/ctfconvert -o $@ $@

$(OBJ_DIR):
	mkdir -p $@

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	gcc -c $(CFLAGS) -o $@ $<

$(OBJ_DIR)/%.o: deps/libcloop/src/%.c | $(OBJ_DIR)
	gcc -c $(CFLAGS) -o $@ $<

#%.o: deps/smartos/src/%.c
#	gcc -c $(CFLAGS) -o $@ $<

$(OBJ_DIR)/illumos_list.a: | deps/illumos-list/.git $(OBJ_DIR)
	cd deps/illumos-list && $(MAKE) BUILD_DIR=$(TOP)/$(OBJ_DIR)

$(OBJ_DIR)/libcbuf.a: | deps/libcbuf/.git $(OBJ_DIR)
	cd deps/libcbuf && $(MAKE) OBJ_DIR=$(TOP)/$(OBJ_DIR) \
	    DESTDIR=$(TOP)/$(OBJ_DIR)

deps/%/.git:
	git submodule update --init --recursive

clean:
	rm -f $(PROG)
	rm -f $(OBJ_DIR)/*.o

clobber: clean
	cd deps/illumos-list && $(MAKE) clean
	rm -rf $(OBJ_DIR)
