
export CFLAGS += -std=c99 -Wall -Wextra -Wno-missing-field-initializers -Itest/aw-base64 -Itest/aw-fiber -Itest/aw-sha

ifeq ($(shell uname -s),Darwin)
export LDFLAGS += -framework Security
endif

ifneq ($(findstring CYGWIN,$(shell uname -s)),)
export LDLIBS += advapi32.lib
endif

test: test.o ioloop.c aw-debug/libaw-debug.a aw-socket/libaw-socket.a ../libaw-websocket.a
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c aw-base64/aw-base64.h aw-debug/aw-debug.h aw-fiber/aw-fiber.h aw-sha/aw-sha1.h aw-socket/aw-socket.h
	$(CC) $(CFLAGS) -I.. -Iaw-base64 -Iaw-debug -Iaw-fiber -Iaw-sha -Iaw-socket -c $< -o $@

../libaw-websocket.a:
	$(MAKE) -C..

aw-base64/aw-base64.h:
	git clone https://github.com/afterwise/aw-base64.git && \
	touch -c $@

aw-debug/libaw-debug.a:
	$(MAKE) -Caw-debug

aw-debug/aw-debug.h:
	git clone https://github.com/afterwise/aw-debug.git && \
	touch -c $@

aw-fiber/aw-fiber.h:
	git clone https://github.com/afterwise/aw-fiber.git && \
	touch -c $@

aw-sha/aw-sha1.h:
	git clone https://github.com/afterwise/aw-sha.git && \
	touch -c $@

aw-socket/libaw-socket.a:
	$(MAKE) -Caw-socket

aw-socket/aw-socket.h:
	git clone https://github.com/afterwise/aw-socket.git && \
	touch -c $@

.PHONY: clean
clean:
	rm -f test test.o

.PHONY: distclean
distclean: clean
	rm -rf aw-base64 aw-debug aw-fiber aw-sha aw-socket

