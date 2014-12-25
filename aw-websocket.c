
/*
   Copyright (c) 2014 Malte Hildingsson, malte (at) afterwi.se

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
#include "aw-sha1.h"

#include <errno.h>
#include <string.h>

#define WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WEBSOCKET_VERSION "Sec-WebSocket-Version: "
#define WEBSOCKET_KEY "Sec-WebSocket-Key: "
#define WEBSOCKET_PROTOCOL "Sec-WebSocket-Protocol: "
#define WEBSOCKET_ACCEPT "Sec-WebSocket-Accept: "
#define WEBSOCKET_RESPONSE \
	"HTTP/1.1 101 Switching Protocols\r\n" \
	"Upgrade: websocket\r\n" \
	"Connection: Upgrade\r\n"

ssize_t websocket_readrequest(const void *src, size_t len) {
	const char *end;

	if (strncmp((char *) src, "GET", 3) != 0)
		return -EBADMSG;

	if ((end = strnstr((char *) src, "\r\n\r\n", len)) == NULL)
		return -EBADMSG;

	return (end + 4) - (char *) src;
}

ssize_t websocket_writeresponse(void *dst, size_t size, const void *src, size_t len) {
	ssize_t tmp, off = 0;
	const char *end = (const char *) src + len, *rp, *ep;
	unsigned char h[SHA1_SIZE];

	if ((rp = strnstr((char *) src, WEBSOCKET_VERSION, end - (char *) src)) == NULL ||
			strncmp(rp + sizeof WEBSOCKET_VERSION - 1, "13\r\n", 4) != 0)
		return -ENOTSUP;

	if ((off = websocket_writedata(dst, off, size, WEBSOCKET_RESPONSE, sizeof WEBSOCKET_RESPONSE - 1)) < 0)
		return off;

	if ((rp = strnstr((char *) src, WEBSOCKET_PROTOCOL, end - (char *) src)) != NULL) {
		rp += sizeof WEBSOCKET_PROTOCOL - 1;

		if ((ep = strnstr(rp, "\r\n", end - rp)) == NULL)
			return -EBADMSG;

		if ((off = websocket_writedata(dst, off, size, WEBSOCKET_PROTOCOL, sizeof WEBSOCKET_PROTOCOL - 1)) < 0)
			return off;

		if ((off = websocket_writedata(dst, off, size, rp, ep - rp)) < 0)
			return off;

		if ((off = websocket_writedata(dst, off, size, "\r\n", 2)) < 0)
			return off;
	}

	if ((rp = strnstr((char *) src, WEBSOCKET_KEY, end - (char *) src)) == NULL ||
			(ep = strnstr(rp, "\r\n", end - rp)) == NULL)
		return -EBADMSG;

	rp += sizeof WEBSOCKET_KEY - 1;
	tmp = off;

	if ((off = websocket_writedata(dst, off, size, rp, ep - rp)) < 0)
		return off;

	if ((off = websocket_writedata(dst, off, size, WEBSOCKET_GUID, sizeof WEBSOCKET_GUID - 1)) < 0)
		return off;

	sha1(h, (unsigned char *) dst + tmp, (ep - rp) + sizeof WEBSOCKET_GUID - 1);
	off = tmp;

	if ((off = websocket_writedata(dst, off, size, WEBSOCKET_ACCEPT, sizeof WEBSOCKET_ACCEPT - 1)) < 0)
		return off;

	if (size - off < base64len(sizeof h))
		return -ENOMEM;

	off += base64((char *) dst + off, base64len(sizeof h), h, sizeof h);

	if ((off = websocket_writedata(dst, off, size, "\r\n\r\n", 4)) < 0)
		return off;

	return off;
}

ssize_t websocket_writeframe(void *dst, size_t size, struct websocket_frame *frame) {
	ssize_t off = 0;
	unsigned char len[8];

	if (size < sizeof frame->header + 8 + sizeof frame->mask)
		return -ENOMEM;

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

	frame->offset = 0;

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

ssize_t websocket_maskdata(void *p, size_t n, struct websocket_frame *frame) {
	size_t i;

	if (frame->header[1] & WEBSOCKET_MASK)
		for (i = 0; i < n; ++i)
			((unsigned char *) p)[i] =
				((unsigned char *) p)[i] ^ frame->mask[frame->offset + i & 3];

	return n;
}

ssize_t websocket_readdata(void *dst, size_t len, const void *src, size_t off, size_t size) {
	if (size - off < len)
		return -EMSGSIZE;

	memcpy(dst, (const unsigned char *) src + off, len);
	return off += len;
}

ssize_t websocket_writedata(void *dst, size_t off, size_t size, const void *src, size_t len) {
	if (size - off < len)
		return -ENOMEM;

	memcpy((unsigned char *) dst + off, src, len);
	return off += len;
}
