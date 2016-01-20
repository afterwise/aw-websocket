
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

#ifndef AW_WEBSOCKET_H
#define AW_WEBSOCKET_H

#include <sys/types.h>

#if __GNUC__
# define _websocket_alwaysinline inline __attribute__((always_inline))
#elif _MSC_VER
# define _websocket_alwaysinline __forceinline
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define WEBSOCKET_NONCESIZE (16)

/* header[0] */
#define WEBSOCKET_FIN (0x80)
#define WEBSOCKET_RSV1 (0x40)
#define WEBSOCKET_RSV2 (0x20)
#define WEBSOCKET_RSV3 (0x10)
#define WEBSOCKET_OPCODE (0x0f)

/* header[1] */
#define WEBSOCKET_MASK (0x80)
#define WEBSOCKET_LENGTH (0x7f)

/* opcode */
#define WEBSOCKET_CONTINUATION (0x00)
#define WEBSOCKET_TEXT (0x01)
#define WEBSOCKET_BINARY (0x02)
#define WEBSOCKET_CLOSE (0x08)
#define WEBSOCKET_PING (0x09)
#define WEBSOCKET_PONG (0x0a)

/* errors */
enum {
	WEBSOCKET_NO_DATA = -1,
	WEBSOCKET_NO_BUFFER_SPACE = -2,
	WEBSOCKET_UNSUPPORTED_VERSION = -3,
	WEBSOCKET_DATA_ERROR = -4
};

/* Low-level nuts and bolts api */

struct websocket_frame {
	unsigned long long length;
	unsigned char header[2];
	unsigned char mask[4];
};

ssize_t websocket_readrequest(const void *src, size_t len);
ssize_t websocket_writerequest(
	void *dst, size_t size, const unsigned char nonce[static WEBSOCKET_NONCESIZE],
	const char *uri, const char *fields[], size_t count);

ssize_t websocket_readresponse(
	const void *src, size_t len, const unsigned char nonce[static WEBSOCKET_NONCESIZE]);
ssize_t websocket_writeresponse(void *dst, size_t size, const void *src, size_t len);

ssize_t websocket_writeframe(void *dst, size_t size, struct websocket_frame *frame);
ssize_t websocket_readframe(const void *src, size_t len, struct websocket_frame *frame);

ssize_t websocket_maskdata(void *p, size_t n, const struct websocket_frame *frame, size_t off);
ssize_t websocket_readdata(void *dst, size_t len, const void *src, size_t off, size_t size);
ssize_t websocket_writedata(void *dst, size_t off, size_t size, const void *src, size_t len);

/* High-level state machine api */

struct websocket_state {
	size_t offset;
	struct websocket_frame frame;
	unsigned short co;
};

struct websocket_result {
	ssize_t dstlen;
	ssize_t srclen;
	int error;
};

typedef ssize_t (*websocket_callback_t)(
	int op, void *dst, size_t size, const void *src, size_t len, void *udata);

_websocket_alwaysinline
void websocket_state_init(struct websocket_state *state) {
	*state = (struct websocket_state) {0};
}

struct websocket_result websocket_update(
	struct websocket_state *state, void *dst, size_t size, void *src, size_t len,
	websocket_callback_t cb, void *udata);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AW_WEBSOCKET_H */

