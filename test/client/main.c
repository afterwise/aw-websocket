
#include "aw-debug.h"
#include "aw-socket.h"
#include "client.h"
#include "ioloop.h"
#if __APPLE__
# include <Security/Security.h>
#elif _WIN32
# include <wincrypt.h>
#endif
#include <errno.h>
#include <stdio.h>
#include <string.h>

static ssize_t randombytes(void *p, size_t n) {
#if __APPLE__
	return SecRandomCopyBytes(kSecRandomDefault, n, p);
#elif _WIN32
	HCRYPTPROV prov;

	if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		return -1;

	CryptGenRandom(prov, n, p);
	CryptReleaseContext(prov, 0);
	return 0;
#endif
}

static ssize_t process_request(struct client *client, void *p, size_t n) {
	ssize_t err;
	size_t len;
	char buf[2048];

	if ((err = websocket_readrequest(p, n)) < 0)
		return printf("[%d] websocket_readrequest err=%zd\n", getpid(), err), err;

	len = err;

	if ((err = websocket_writeresponse(buf, sizeof buf, p, len)) < 0)
		return printf("[%d] websocket_writehandshake err=%zd\n", getpid(), err), err;

	if ((err = socket_send(client->sd, buf, err)) < 0)
		return printf("[%d] socket_send err=%zd\n", getpid(), err), err;

	client->state = FRAME;
	return len;
}

static ssize_t process_response(struct client *client, void *p, size_t n) {
	ssize_t err;
	size_t len;

	printf("[%d] -> process response:\n", getpid());
	debug_hex(p, n);

	if ((err = websocket_readresponse(p, n, client->nonce)) < 0)
		return printf("[%d] websocket_readresponse err=%zd\n", getpid(), err), err;

	len = err;
	client->state = FRAME;

	return len;
}

static ssize_t process_frame(struct client *client, void *p, size_t n) {
	ssize_t err;
	size_t len;
	char buf[2048];

	if ((err = websocket_readframe(p, n, &client->frame)) < 0) {
		if (err == -EMSGSIZE)
			return client->more = 1, 0;
		return printf("[%d] websocket_readframe err=%zd\n", getpid(), err), err;
	}

	len = err;
	p += err;
	n -= err;
	client->off = 0;

	printf("[%d] -> process frame: %s\n",
		getpid(), client_opcode_names[client->frame.header[0] & WEBSOCKET_OPCODE]);

	if ((client->frame.header[0] & WEBSOCKET_OPCODE) == WEBSOCKET_CLOSE) {
		if ((err = websocket_writeframe(buf, sizeof buf, &client->frame)) < 0)
			return printf("[%d] websocket_writeframe err=%zd\n", getpid(), err), err;

		if ((err = socket_send(client->sd, buf, err)) < 0)
			return printf("[%d] socket_send err=%zd\n", getpid(), err), err;

		client->state = CLOSE;
		client->close = 1;
	} else if ((client->frame.header[0] & WEBSOCKET_OPCODE) == WEBSOCKET_PING) {
		client->frame.header[0] = WEBSOCKET_FIN | WEBSOCKET_PONG;

		if ((err = websocket_writeframe(buf, sizeof buf, &client->frame)) < 0)
			return printf("[%d] websocket_writeframe err=%zd\n", getpid(), err), err;

		if ((err = socket_send(client->sd, buf, err)) < 0)
			return printf("[%d] socket_send err=%zd\n", getpid(), err), err;

		if (client->frame.length > 0)
			client->state = ECHO;
	} else if ((client->frame.header[0] & WEBSOCKET_OPCODE) == WEBSOCKET_PONG)
		client->state = IGNORE;
	else if ((client->frame.header[0] & WEBSOCKET_OPCODE) == WEBSOCKET_CONTINUATION)
		client->state = IGNORE;
	else if ((client->frame.header[0] & WEBSOCKET_OPCODE) == WEBSOCKET_TEXT)
		client->state = DATA;
	else if ((client->frame.header[0] & WEBSOCKET_OPCODE) == WEBSOCKET_BINARY)
		client->state = DATA;
	else
		return -1;

	return len;
}

static ssize_t process_data(struct client *client, char *p, size_t n) {
	char tbuf[2048];
	size_t tn = 0;
	ssize_t err;
	size_t len;

	if ((len = client->frame.length - client->off) > n)
		len = n;

	websocket_maskdata(p, len, &client->frame, client->off);
	client->off += len;

	memcpy(tbuf + tn, p, len);
	tn += len;

	p += len;
	n -= len;

	if (client->state == ECHO) {
		if ((err = socket_send(client->sd, tbuf, tn)) < 0)
			return printf("[%d] socket_send err=%zd\n", getpid(), err), err;
		tn = 0;
	}

	if (client->off == client->frame.length) {
		if (client->state == DATA) {
			tbuf[tn] = 0;
			printf("[%d] -> data:\n", getpid());
			debug_hex(tbuf, tn);
			tn = 0;
		} else if (client->state == CLOSE) {
			tbuf[tn] = 0;
			printf("[%d] -> close:\n", getpid());
			debug_hex(tbuf, tn);
			tn = 0;
			tbuf[tn] = 0;
			tn = 0;
		}

		client->state = FRAME;
	}

	return len;
}

static ssize_t send_hello(struct client *client) {
	ssize_t err, off = 0;
	char data[] = "HELLO WORLD!";
	char buf[2048];

	printf("[%d] <- send text:\n", getpid());
	debug_hex(data, sizeof data - 1);

	memset(&client->frame, 0, sizeof client->frame);
	client->frame.length = sizeof data - 1;
	client->frame.header[0] = WEBSOCKET_FIN | WEBSOCKET_TEXT;

	if ((off = websocket_writeframe(buf, sizeof buf, &client->frame)) < 0)
		return printf("[%d] websocket_writeframe err=%zd\n", getpid(), off), off;

	if ((off = websocket_writedata(buf, off, sizeof buf, data, sizeof data - 1)) < 0)
		return printf("[%d] websocket_writedata err=%zd\n", getpid(), off), off;

	if ((err = socket_send(client->sd, buf, off)) < 0)
		return printf("[%d] socket_send err=%zd\n", getpid(), err), err;

	return err;
}

static ssize_t handle_data(void *p, size_t len, size_t size, void *cookie) {
	struct client *client = cookie;
	ssize_t err;

	(void) size;

	printf("[%d] -> handle data: %s\n", getpid(), client_state_names[client->state]);

	if (client->state == REQUEST) {
		if ((err = process_request(client, p, len)) < 0)
			return err;
	} else if (client->state == RESPONSE) {
		if ((err = process_response(client, p, len)) < 0)
			return err;
		send_hello(client);
	} else if (client->state == FRAME) {
		if ((err = process_frame(client, p, len)) < 0)
			return err;
	} else {
		if ((err = process_data(client, p, len)) < 0)
			return err;
	}

	return err;
}

static ssize_t read_socket(ssize_t fd, void *p, size_t n, void *cookie) {
	(void) cookie;
	return socket_recv((int) fd, p, n, 0);
}

int main(int argc, char *argv[]) {
	struct client client;
	ssize_t err;
	char buf[2048];

	(void) argc;
	(void) argv;

	memset(&client, 0, sizeof client);
	socket_init();

	if ((client.sd = socket_connect("echo.websocket.org", "http", SOCKET_STREAM)) < 0)
		return fprintf(stderr, "connect failed\n"), 1;

	if (randombytes(client.nonce, sizeof client.nonce) < 0)
		return fprintf(stderr, "randombytes failed\n"), 1;

	if ((err = websocket_writerequest(
			buf, sizeof buf, client.nonce,
			"ws://echo.websocket.org/?encoding=text",
			NULL, 0)) < 0)
		return fprintf(stderr, "websocket_writerequest failed\n"), 1;

	printf("[%d] <- send request:\n", getpid());
	debug_hex(buf, err);

	err = socket_send(client.sd, buf, err);

	client.state = RESPONSE;
	err = ioloop(client.sd, buf, sizeof buf, &read_socket, &handle_data, &client);
	socket_close(client.sd);

	printf("[%d] done\n", getpid());
	return 0;
}

