/*
 * Unit tests for the generic vPCI handler code.
 *
 * Copyright (C) 2017 Citrix Systems R&D
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _TEST_VPCI_
#define _TEST_VPCI_

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>

#define container_of(ptr, type, member) ({                      \
        typeof( ((type *)0)->member ) *__mptr = (ptr);          \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#include "rbtree.h"

struct pci_dev {
    struct domain *domain;
    struct vpci *vpci;
};

struct domain {
    struct pci_dev pdev;
};

struct vcpu
{
    struct domain *domain;
};

extern struct vcpu v;

#define spin_lock(x)
#define spin_unlock(x)
#define spin_is_locked(x) true

#define current (&v)

#define has_vpci(d) true

#include "vpci.h"

#define xzalloc(type) (type *)calloc(1, sizeof(type))
#define xfree(p) free(p)

#define EXPORT_SYMBOL(x)

#define pci_get_pdev_by_domain(d, ...) &(d)->pdev

#define atomic_read(x) 1

/* Dummy native helpers. Writes are ignored, reads return 1's. */
#define pci_conf_read8(...) (0xff)
#define pci_conf_read16(...) (0xffff)
#define pci_conf_read32(...) (0xffffffff)
#define pci_conf_write8(...)
#define pci_conf_write16(...)
#define pci_conf_write32(...)

#define BUG() assert(0)
#define ASSERT_UNREACHABLE() assert(0)
#define ASSERT(x) assert(x)

#ifdef _LP64
#define BITS_PER_LONG 64
#else
#define BITS_PER_LONG 32
#endif
#define GENMASK(h, l) \
    (((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

#define min(x,y) ({ \
        const typeof(x) _x = (x);       \
        const typeof(y) _y = (y);       \
        (void) (&_x == &_y);            \
        _x < _y ? _x : _y; })

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

