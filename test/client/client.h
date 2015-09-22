
#ifndef CLIENT_H
#define CLIENT_H

#include "aw-websocket.h"

#define REQUEST (0)
#define RESPONSE (1)
#define FRAME (2)
#define DATA (3)
#define ECHO (4)
#define IGNORE (5)
#define CLOSE (6)

struct client {
	unsigned char state;
	unsigned char more;
	unsigned char close;
	int sd;
	size_t off;
	struct websocket_frame frame;
	unsigned char nonce[WEBSOCKET_NONCESIZE];
};

static const char *client_state_names[] = {
	"REQUEST", "RESPONSE", "FRAME", "DATA", "ECHO", "IGNORE", "CLOSE"
};

static const char *client_opcode_names[] = {
	"CONTINUATION", "TEXT", "BINARY", NULL, NULL, NULL, NULL, NULL, "CLOSE", "PING", "PONG"
};

#endif /* CLIENT_H */

