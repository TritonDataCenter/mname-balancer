#
# Custom Makefile for illumos libbunyan.
#

BUILD_DIR ?=	build
LIBFILE =	$(BUILD_DIR)/illumos_bunyan.a
PROVIDER_D =	src/bunyan_provider.d
PROVIDER_H =	$(BUILD_DIR)/bunyan_provider_impl.h
PROVIDER_O =	$(BUILD_DIR)/bunyan_provider.o
OBJECTS =	$(BUILD_DIR)/bunyan.o $(BUILD_DIR)/nvpair_json.o
HEADERS =	include/bunyan.h $(PROVIDER_H)
AR ?=		ar
DTRACE ?=	dtrace

CFLAGS +=	-std=c99 -D__EXTENSIONS__

CPPFLAGS +=	-I./include
CPPFLAGS +=	-I$(BUILD_DIR)

$(LIBFILE): $(OBJECTS) $(PROVIDER_O)
	$(AR) rcs $@ $^

$(OBJECTS): $(BUILD_DIR)/%.o: src/%.c $(HEADERS) | $(BUILD_DIR)
	$(CC) -o $@ -c $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $<

$(PROVIDER_H): $(PROVIDER_D) | $(BUILD_DIR)
	$(DTRACE) -h -o $@ -s $<

$(PROVIDER_O): $(PROVIDER_D) $(OBJECTS) | $(BUILD_DIR)
	$(DTRACE) -G -o $@ -s $< $(OBJECTS)

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -f $(LIBFILE) $(OBJECTS) $(PROVIDER_O) $(PROVIDER_H)
