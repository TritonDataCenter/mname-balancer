

TOP =		$(PWD)


PROG =		bbal

OBJS =		main.o \
		cloop.o \
		cserver.o

DEPS_LIBS =	illumos_list.a \
		libcbuf.a

LIBS =		$(DEPS_LIBS) -lnsl -lsocket -lumem -lavl

INCS =		$(TOP)/deps/illumos-list/include \
		$(TOP)/deps/libcbuf/include \
		$(TOP)/deps/libcloop/include

CFLAGS =	-Wall -Wextra -Werror \
		-Wno-unused-parameter \
		-std=c99 -D__EXTENSIONS__ \
		-O0 -gdwarf-2 \
		$(INCS:%=-I%)
		#-I$(TOP)/deps/smartos/include \

$(PROG): $(OBJS) $(DEPS_LIBS)
	gcc $(CFLAGS) -o $@ $(OBJS) $(LIBS)
	/opt/ctf/bin/ctfconvert -o $@ $@

%.o: %.c
	gcc -c $(CFLAGS) -o $@ $<

%.o: deps/libcloop/src/%.c
	gcc -c $(CFLAGS) -o $@ $<

#%.o: deps/smartos/src/%.c
#	gcc -c $(CFLAGS) -o $@ $<

illumos_list.a: | deps/illumos-list/.git
	cd deps/illumos-list && $(MAKE) BUILD_DIR=$(TOP)

libcbuf.a: | deps/libcbuf/.git
	cd deps/libcbuf && $(MAKE) OBJ_DIR=$(TOP) DESTDIR=$(TOP)

deps/%/.git:
	git submodule update --init --recursive

clean:
	rm -f $(PROG)
	rm -f *.o

clobber: clean
	cd deps/illumos-list && $(MAKE) clean
	rm -f $(DEPS_LIBS)
