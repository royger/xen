/******************************************************************************
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (C) 2005 Rusty Russell IBM Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "xenstored_core.h"

#define XENSTORED_DEV  "/dev/xen/xenstored"

evtchn_port_t xenbus_evtchn(void)
{
	int fd;
	int rc;
	evtchn_port_t port;
	char str[20];

	fd = open(XENSTORED_DEV, O_RDONLY);
	if (fd == -1)
		return -1;

	rc = read(fd, str, sizeof(str) - 1);
	if (rc == -1)
	{
		int err = errno;
		close(fd);
		errno = err;
		return -1;
	}

	str[rc] = '\0';
	port = strtoul(str, NULL, 0);

	close(fd);
	return port;
}

void *xenbus_map(void)
{
	int fd;
	void *addr;

	fd = open(XENSTORED_DEV, O_RDWR);
	if (fd == -1)
		return NULL;

	addr = mmap(NULL, getpagesize(), PROT_READ|PROT_WRITE,
		MAP_SHARED, fd, 0);

	if (addr == MAP_FAILED)
		addr = NULL;

	close(fd);

	return addr;
}

void xenbus_notify_running(void)
{
}
