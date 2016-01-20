
/*
   Copyright (c) 2014-2015 Malte Hildingsson, malte (at) afterwi.se

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
 */

#include "aw-websocket.h"
#include "aw-base64.h"
#include "aw-fiber.h"
#include "aw-sha1.h"

#include <string.h>

#define WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WEBSOCKET_VERSION "Sec-WebSocket-Version: "
#define WEBSOCKET_KEY "Sec-WebSocket-Key: "
#define WEBSOCKET_PROTOCOL "Sec-WebSocket-Protocol: "
#define WEBSOCKET_ACCEPT "Sec-WebSocket-Accept: "
#define WEBSOCKET_REQUEST \
	"GET HTTP/1.1\r\n" \
	"Connection: Upgrade\r\n" \
	"Upgrade: websocket\r\n"
#define WEBSOCKET_RESPONSE \
	"HTTP/1.1 101 Switching Protocols\r\n" \
	"Connection: Upgrade\r\n" \
	"Upgrade: websocket\r\n"

ssize_t websocket_readrequest(const void *src, size_t len) {
	const char *end;

	if (strncmp((char *) src, "GET", 3) != 0)
		return WEBSOCKET_DATA_ERROR;

	if ((end = strnstr((char *) src, "\r\n\r\n", len)) == NULL)
		return WEBSOCKET_DATA_ERROR;

	return (end + 4) - (char *) src;
}

ssize_t websocket_writerequest(
		void *dst, size_t size, const unsigned char nonce[static WEBSOCKET_NONCESIZE],
		const char *uri, const char *fields[], size_t count) {
	ssize_t off = 0;
	size_t i;

	if ((off = websocket_writedata(dst, off, size, WEBSOCKET_REQUEST, 4)) < 0)
		return off;

	if ((off = websocket_writedata(dst, off, size, uri, strlen(uri))) < 0)
		return off;

	if ((off = websocket_writedata(dst, off, size, WEBSOCKET_REQUEST + 3, sizeof WEBSOCKET_REQUEST - 4)) < 0)
		return off;

	if ((off = websocket_writedata(dst, off, size, WEBSOCKET_KEY, sizeof WEBSOCKET_KEY - 1)) < 0)
		return off;

	if (size - off < base64len(WEBSOCKET_NONCESIZE))
		return WEBSOCKET_NO_BUFFER_SPACE;

	off += base64((char *) dst + off, base64len(WEBSOCKET_NONCESIZE), nonce, WEBSOCKET_NONCESIZE);

	if ((off = websocket_writedata(dst, off, size, "\r\n", 2)) < 0)
		return off;

	if ((off = websocket_writedata(dst, off, size, WEBSOCKET_VERSION, sizeof WEBSOCKET_VERSION - 1)) < 0)
		return off;

	if ((off = websocket_writedata(dst, off, size, "13\r\n", 4)) < 0)
		return off;

	if (fields != NULL)
		for (i = 0; i < count; ++i) {
			if ((off = websocket_writedata(dst, off, size, fields[i], strlen(fields[i]))) < 0)
				return off;

			if ((off = websocket_writedata(dst, off, size, "\r\n", 2)) < 0)
				return off;
		}

	if ((off = websocket_writedata(dst, off, size, "\r\n", 2)) < 0)
		return off;

	return off;
}

static ssize_t acceptkey(
		unsigned char h[SHA1_SIZE], void *buf, ssize_t off, size_t size,
		const char *key, size_t len) {
	size_t tmp = off;

	if ((off = websocket_writedata(buf, off, size, key, len)) < 0)
		return off;

	if ((off = websocket_writedata(buf, off, size, WEBSOCKET_GUID, sizeof WEBSOCKET_GUID - 1)) < 0)
		return off;

	sha1(h, (unsigned char *) buf + tmp, len + sizeof WEBSOCKET_GUID - 1);
	return tmp;
}

static ssize_t acceptnonce(
		unsigned char h[SHA1_SIZE], void *buf, ssize_t off, size_t size,
		const unsigned char nonce[static WEBSOCKET_NONCESIZE]) {
	if (size - off < base64len(WEBSOCKET_NONCESIZE))
		return WEBSOCKET_NO_BUFFER_SPACE;

	base64((char *) buf + off, base64len(WEBSOCKET_NONCESIZE), nonce, WEBSOCKET_NONCESIZE);
	return acceptkey(h, buf, off, size, (char *) buf + off, base64len(WEBSOCKET_NONCESIZE));
}

ssize_t websocket_readresponse(
		const void *src, size_t len, const unsigned char nonce[static WEBSOCKET_NONCESIZE]) {
	ssize_t off;
	const char *end = (const char *) src + len, *rp, *ep;
	unsigned char h[SHA1_SIZE];
	char buf[64];

	if ((rp = strnstr((char *) src, WEBSOCKET_ACCEPT, end - (char *) src)) == NULL ||
			(ep = strnstr(rp, "\r\n", end - rp)) == NULL)
		return WEBSOCKET_DATA_ERROR;

	if ((off = acceptnonce(h, buf, 0, sizeof buf, nonce)) < 0)
		return off;

	if ((end = strnstr((char *) src, "\r\n\r\n", len)) == NULL)
		return WEBSOCKET_DATA_ERROR;

	return (end + 4) - (char *) src;
}

ssize_t websocket_writeresponse(void *dst, size_t size, const void *src, size_t len) {
	ssize_t off = 0;
	const char *end = (const char *) src + len, *rp, *ep;
	unsigned char h[SHA1_SIZE];

	if ((rp = strnstr((char *) src, WEBSOCKET_VERSION, end - (char *) src)) == NULL ||
			strncmp(rp + sizeof WEBSOCKET_VERSION - 1, "13\r\n", 4) != 0)
		return WEBSOCKET_UNSUPPORTED_VERSION;

	if ((off = websocket_writedata(dst, off, size, WEBSOCKET_RESPONSE, sizeof WEBSOCKET_RESPONSE - 1)) < 0)
		return off;

	if ((rp = strnstr((char *) src, WEBSOCKET_PROTOCOL, end - (char *) src)) != NULL) {
		rp += sizeof WEBSOCKET_PROTOCOL - 1;

		if ((ep = strnstr(rp, "\r\n", end - rp)) == NULL)
			return WEBSOCKET_DATA_ERROR;

		if ((off = websocket_writedata(dst, off, size, WEBSOCKET_PROTOCOL, sizeof WEBSOCKET_PROTOCOL - 1)) < 0)
			return off;

		if ((off = websocket_writedata(dst, off, size, rp, ep - rp)) < 0)
			return off;

		if ((off = websocket_writedata(dst, off, size, "\r\n", 2)) < 0)
			return off;
	}

	if ((rp = strnstr((char *) src, WEBSOCKET_KEY, end - (char *) src)) == NULL ||
			(ep = strnstr(rp, "\r\n", end - rp)) == NULL)
		return WEBSOCKET_DATA_ERROR;

	rp += sizeof WEBSOCKET_KEY - 1;

	if ((off = acceptkey(h, dst, off, size, rp, ep - rp)) < 0)
		return off;

	if ((off = websocket_writedata(dst, off, size, WEBSOCKET_ACCEPT, sizeof WEBSOCKET_ACCEPT - 1)) < 0)
		return off;

	if (size - off < base64len(sizeof h))
		return WEBSOCKET_NO_BUFFER_SPACE;

	off += base64((char *) dst + off, base64len(sizeof h), h, sizeof h);

	if ((off = websocket_writedata(dst, off, size, "\r\n\r\n", 4)) < 0)
		return off;

	return off;
}

ssize_t websocket_writeframe(void *dst, size_t size, struct websocket_frame *frame) {
	ssize_t off = 0;
	unsigned char len[8];

	if (size < sizeof frame->header + 8 + sizeof frame->mask)
		return WEBSOCKET_NO_BUFFER_SPACE;

	if (frame->length < 126)
		frame->header[1] |= (unsigned char) frame->length;
	else if (frame->length < 0x10000) {
		frame->header[1] |= 126;
		len[0] = (unsigned char) (frame->length >> 0x08);
		len[1] = (unsigned char) (frame->length >> 0x00);
	} else {
		frame->header[1] |= 127;
		len[0] = (unsigned char) (frame->length >> 0x38);
		len[1] = (unsigned char) (frame->length >> 0x30);
		len[2] = (unsigned char) (frame->length >> 0x28);
		len[3] = (unsigned char) (frame->length >> 0x20);
		len[4] = (unsigned char) (frame->length >> 0x18);
		len[5] = (unsigned char) (frame->length >> 0x10);
		len[6] = (unsigned char) (frame->length >> 0x08);
		len[7] = (unsigned char) (frame->length >> 0x00);
	}

	if ((off = websocket_writedata(dst, off, size, frame->header, sizeof frame->header)) < 0)
		return off;

	if ((frame->header[1] & WEBSOCKET_LENGTH) > 125)
		if ((off = websocket_writedata(dst, off, size, len, 2 + 6 * (frame->header[1] & 1))) < 0)
			return off;

	if (frame->header[1] & WEBSOCKET_MASK)
		if ((off = websocket_writedata(dst, off, size, frame->mask, sizeof frame->mask)) < 0)
			return off;

	return off;
}

ssize_t websocket_readframe(const void *src, size_t len, struct websocket_frame *frame) {
	ssize_t off = 0;
	unsigned char tmp[8];

	if ((off = websocket_readdata(frame->header, sizeof frame->header, src, off, len)) < 0)
		return off;

	if ((frame->header[1] & WEBSOCKET_LENGTH) < 126)
		frame->length = frame->header[1] & WEBSOCKET_LENGTH;
	else if ((frame->header[1] & WEBSOCKET_LENGTH) < 127) {
		if ((off = websocket_readdata(tmp, 2, src, off, len)) < 0)
			return off;

		frame->length = (unsigned long) tmp[1] << 0x00 | (unsigned long) tmp[0] << 0x08;
	} else {
		if ((off = websocket_readdata(tmp, 8, src, off, len)) < 0)
			return off;

		frame->length =
			(unsigned long) tmp[7] << 0x00 | (unsigned long) tmp[6] << 0x08 |
			(unsigned long) tmp[5] << 0x10 | (unsigned long) tmp[4] << 0x18 |
			(unsigned long) tmp[3] << 0x20 | (unsigned long) tmp[2] << 0x28 |
			(unsigned long) tmp[1] << 0x30 | (unsigned long) tmp[0] << 0x38;
	}

	if (frame->header[1] & WEBSOCKET_MASK)
		if ((off = websocket_readdata(frame->mask, sizeof frame->mask, src, off, len)) < 0)
			return off;

	return off;
}

ssize_t websocket_maskdata(void *p, size_t n, const struct websocket_frame *frame, size_t off) {
	size_t i;

	if (frame->header[1] & WEBSOCKET_MASK)
		for (i = 0; i < n; ++i)
			((unsigned char *) p)[i] =
				((unsigned char *) p)[i] ^ frame->mask[off + i & 3];

	return n;
}

ssize_t websocket_readdata(void *dst, size_t len, const void *src, size_t off, size_t size) {
	if (size - off < len)
		return WEBSOCKET_NO_DATA;

	memcpy(dst, (const unsigned char *) src + off, len);
	return off += len;
}

ssize_t websocket_writedata(void *dst, size_t off, size_t size, const void *src, size_t len) {
	if (size - off < len)
		return WEBSOCKET_NO_BUFFER_SPACE;

	memcpy((unsigned char *) dst + off, src, len);
	return off += len;
}

struct websocket_result websocket_update(
		struct websocket_state *state, void *dst, size_t size, void *src, size_t len,
		websocket_callback_t cb, void *udata) {
	size_t dstoff = 0, srcoff = 0;
	ssize_t err;

	coroutine_begin(state->co);

        while ((err = websocket_writeresponse(
			(unsigned char *) dst + dstoff, size - dstoff,
			(const unsigned char *) src + srcoff, len - srcoff)) < 0)
		coroutine_yield(state->co, (struct websocket_result) {dstoff, srcoff, err});
	dstoff += err;

	while ((err = websocket_readrequest((const unsigned char *) src + srcoff, len - srcoff)) < 0)
		coroutine_yield(state->co, (struct websocket_result) {dstoff, srcoff, err});
	srcoff += err;

	for (int loop = 1; loop;) {
		while ((err = websocket_readframe(
				(const unsigned char *) src + srcoff, len - srcoff, &state->frame)) < 0)
			coroutine_yield(state->co, (struct websocket_result) {dstoff, srcoff, err});
		srcoff += err;
		state->offset = 0;

		switch (state->frame.header[0] & WEBSOCKET_OPCODE) {
		case WEBSOCKET_CLOSE:
			while ((err = websocket_writeframe(
					(unsigned char *) dst + dstoff, size - dstoff, &state->frame)) < 0)
				coroutine_yield(state->co, (struct websocket_result) {dstoff, srcoff, err});
			dstoff += err;
			while (state->frame.length - state->offset > len - srcoff) {
				state->offset += len - srcoff;
				srcoff = len;
				coroutine_yield(
					state->co, (struct websocket_result) {dstoff, srcoff, WEBSOCKET_NO_DATA});
			}
			srcoff += state->frame.length - state->offset;
			loop = 0;
			break;
		case WEBSOCKET_PING:
			state->frame.header[0] &= ~WEBSOCKET_PING;
			state->frame.header[0] |= WEBSOCKET_FIN | WEBSOCKET_PONG;
			while ((err = websocket_writeframe(
					(unsigned char *) dst + dstoff, size - dstoff, &state->frame)) < 0)
				coroutine_yield(
					state->co, (struct websocket_result) {dstoff, srcoff, err});
			dstoff += err;
			while (state->frame.length - state->offset > len - srcoff) {
				memcpy(
					(unsigned char *) dst + dstoff, (const unsigned char *) src + srcoff,
					len - srcoff);
				dstoff += len - srcoff;
				state->offset += len - srcoff;
				srcoff = len;
				coroutine_yield(
					state->co, (struct websocket_result) {dstoff, srcoff, WEBSOCKET_NO_DATA});
			}
			memcpy(
				(unsigned char *) dst + dstoff, (const unsigned char *) src + srcoff,
				state->frame.length - state->offset);
			dstoff += state->frame.length - state->offset;
			srcoff += state->frame.length - state->offset;
			break;
		case WEBSOCKET_PONG:
			while (state->frame.length - state->offset > len - srcoff) {
				state->offset += len - srcoff;
				srcoff = len;
				coroutine_yield(
					state->co, (struct websocket_result) {dstoff, srcoff, WEBSOCKET_NO_DATA});
			}
			srcoff += state->frame.length - state->offset;
			break;
		case WEBSOCKET_CONTINUATION:
		case WEBSOCKET_TEXT:
		case WEBSOCKET_BINARY:
			while (state->frame.length - state->offset > len - srcoff) {
				websocket_maskdata(
					(unsigned char *) src + srcoff, len - srcoff, &state->frame, state->offset);
				if (cb != NULL) {
					while ((err = cb((state->frame.header[0] & WEBSOCKET_OPCODE),
							(unsigned char *) dst + dstoff, size - dstoff,
							(const unsigned char *) src + srcoff, len - srcoff,
							udata)) < 0)
						coroutine_yield(
							state->co, (struct websocket_result) {dstoff, srcoff, err});
					dstoff += err;
				}
				state->offset += len - srcoff;
				srcoff = len;
				coroutine_yield(
					state->co, (struct websocket_result) {dstoff, srcoff, WEBSOCKET_NO_DATA});
			}
			websocket_maskdata(
				(unsigned char *) src + srcoff, state->frame.length - state->offset,
				&state->frame, state->offset);
			if (cb != NULL) {
				while ((err = cb((state->frame.header[0] & WEBSOCKET_OPCODE),
						(unsigned char *) dst + dstoff, size - dstoff,
						(const unsigned char *) src + srcoff,
						state->frame.length - state->offset, udata)) < 0)
					coroutine_yield(
						state->co, (struct websocket_result) {dstoff, srcoff, err});
				dstoff += err;
			}
			srcoff += state->frame.length - state->offset;
			break;
		}
	}

	coroutine_end(state->co);
	return (struct websocket_result) {dstoff, srcoff, 0};
}

ssize_t websocket_message(
		unsigned char op, unsigned char mask[4], void *dst, size_t size,
		const void *src, size_t len) {
	struct websocket_frame frame = {len, {op, (mask != NULL ? WEBSOCKET_MASK : 0)}};
	ssize_t off1, off2;
	if ((off1 = websocket_writeframe(dst, size, &frame)) < 0)
		return off1;
	if (mask != NULL)
		if ((off1 = websocket_writedata(dst, off1, size, mask, 4)) < 0)
			return off1;
	if ((off2 = websocket_writedata(dst, off1, size, src, len)) < 0)
		return off2;
	if (mask != NULL)
		websocket_maskdata((unsigned char *) dst + off1, off2 - off1, &frame, 0);
	return off2;
}

