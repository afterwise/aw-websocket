
#include "ioloop.h"
#include <errno.h>
#include <string.h>

ssize_t ioloop(
		ssize_t fd, void *buffer, size_t size, ioloop_read *read,
		ioloop_handle *handle, void *cookie) {
	char *p = buffer;
	size_t n = 0;
	ssize_t err;
	int more = 0;

	for (;;) {
		if (n == 0 || more) {
			if (n == size)
				return -ENOMEM;

			memmove(buffer, p, n);

			if ((err = read(fd, (char *) buffer + n, size - n, cookie)) <= 0)
				return err;

			p = buffer;
			n += err;
			more = 0;
		}

		if ((err = handle(p, n, size, cookie)) < 0) {
			if (err != -EAGAIN)
				return err;

			more = 1;
		}

		p += err;
		n -= err;
	}
}

