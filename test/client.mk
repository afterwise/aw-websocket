
PROGRAMS += Client

CLIENTLIBS = \
	libaw-debug \
	libaw-socket \
	libaw-websocket \
	libminiz

ifneq ($(findstring darwin, $(TARGET)),)
Client.%: FRAMEWORKS += Security
endif

ifneq ($(findstring win32-, $(TARGET)),)
Client.%: LDLIBS += advapi32.lib
endif

Client.%: client/libclient.%$(LIBSUF) $(patsubst %, extern/%$(EXESUF)$(LIBSUF), $(CLIENTLIBS))
	$(link)

