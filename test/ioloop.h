
#ifndef IOLOOP_H
#define IOLOOP_H

#include <sys/types.h>

typedef ssize_t (ioloop_read)(ssize_t fd, void *p, size_t size, void *cookie);
typedef ssize_t (ioloop_handle)(void *p, size_t len, size_t size, void *cookie);

ssize_t ioloop(
	ssize_t fd, void *buffer, size_t size, ioloop_read *read,
	ioloop_handle *handle, void *cookie);

#endif /* IOLOOP_H */

