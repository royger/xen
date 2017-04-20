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

#include "emul.h"

/* Single vcpu (current), and single domain with a single PCI device. */
static struct vpci vpci = {
    .handlers = RB_ROOT,
};

static struct domain d = {
    .pdev.domain = &d,
    .pdev.vpci = &vpci,
};

struct vcpu v = { .domain = &d };

/* Dummy hooks, write stores data, read fetches it. */
static int vpci_read8(struct pci_dev *pdev, unsigned int reg,
                      union vpci_val *val, void *data)
{
    uint8_t *priv = data;

    val->half_word = *priv;
    return 0;
}

static int vpci_write8(struct pci_dev *pdev, unsigned int reg,
                       union vpci_val val, void *data)
{
    uint8_t *priv = data;

    *priv = val.half_word;
    return 0;
}

static int vpci_read16(struct pci_dev *pdev, unsigned int reg,
                       union vpci_val *val, void *data)
{
    uint16_t *priv = data;

    val->word = *priv;
    return 0;
}

static int vpci_write16(struct pci_dev *pdev, unsigned int reg,
                        union vpci_val val, void *data)
{
    uint16_t *priv = data;

    *priv = val.word;
    return 0;
}

static int vpci_read32(struct pci_dev *pdev, unsigned int reg,
                       union vpci_val *val, void *data)
{
    uint32_t *priv = data;

    val->double_word = *priv;
    return 0;
}

static int vpci_write32(struct pci_dev *pdev, unsigned int reg,
                        union vpci_val val, void *data)
{
    uint32_t *priv = data;

    *priv = val.double_word;
    return 0;
}

#define VPCI_READ(reg, size, data) \
    assert(!xen_vpci_read(0, 0, 0, reg, size, data))

#define VPCI_READ_CHECK(reg, size, expected) ({ \
    uint32_t val;                               \
    VPCI_READ(reg, size, &val);                 \
    assert(val == expected);                    \
    })

#define VPCI_WRITE(reg, size, data) \
    assert(!xen_vpci_write(0, 0, 0, reg, size, data))

#define VPCI_CHECK_REG(reg, size, data) ({      \
    VPCI_WRITE(reg, size, data);                \
    VPCI_READ_CHECK(reg, size, data);           \
    })

#define VPCI_ADD_REG(fread, fwrite, off, size, store)                         \
    assert(!xen_vpci_add_register(&d.pdev, fread, fwrite, off, size, &store)) \

#define VPCI_ADD_INVALID_REG(fread, fwrite, off, size)                      \
    assert(xen_vpci_add_register(&d.pdev, fread, fwrite, off, size, NULL))  \

int
main(int argc, char **argv)
{
    /* Index storage by offset. */
    uint32_t r0 = 0xdeadbeef;
    uint8_t r5 = 0xef;
    uint8_t r6 = 0xbe;
    uint8_t r7 = 0xef;
    uint16_t r12 = 0x8696;
    int rc;

    VPCI_ADD_REG(vpci_read32, vpci_write32, 0, 4, r0);
    VPCI_READ_CHECK(0, 4, 0xdeadbeef);
    VPCI_CHECK_REG(0, 4, 0xbcbcbcbc);

    VPCI_ADD_REG(vpci_read8, vpci_write8, 5, 1, r5);
    VPCI_READ_CHECK(5, 1, 0xef);
    VPCI_CHECK_REG(5, 1, 0xba);

    VPCI_ADD_REG(vpci_read8, vpci_write8, 6, 1, r6);
    VPCI_READ_CHECK(6, 1, 0xbe);
    VPCI_CHECK_REG(6, 1, 0xba);

    VPCI_ADD_REG(vpci_read8, vpci_write8, 7, 1, r7);
    VPCI_READ_CHECK(7, 1, 0xef);
    VPCI_CHECK_REG(7, 1, 0xbd);

    VPCI_ADD_REG(vpci_read16, vpci_write16, 12, 2, r12);
    VPCI_READ_CHECK(12, 2, 0x8696);
    VPCI_READ_CHECK(12, 4, 0xffff8696);

    /*
     * At this point we have the following layout:
     *
     * 32    24    16     8     0
     *  +-----+-----+-----+-----+
     *  |          r0           | 0
     *  +-----+-----+-----+-----+
     *  | r7  |  r6 |  r5 |/////| 32
     *  +-----+-----+-----+-----|
     *  |///////////////////////| 64
     *  +-----------+-----------+
     *  |///////////|    r12    | 96
     *  +-----------+-----------+
     *             ...
     *  / = empty.
     */

    /* Try to add an overlapping register handler. */
    VPCI_ADD_INVALID_REG(vpci_read32, vpci_write32, 4, 4);

    /* Try to add a non-aligned register. */
    VPCI_ADD_INVALID_REG(vpci_read16, vpci_write16, 15, 2);

    /* Try to add a register with wrong size. */
    VPCI_ADD_INVALID_REG(vpci_read16, vpci_write16, 8, 3);

    /* Try to add a register with missing handlers. */
    VPCI_ADD_INVALID_REG(vpci_read16, NULL, 8, 2);
    VPCI_ADD_INVALID_REG(NULL, vpci_write16, 8, 2);

    /* Read/write of unset register. */
    VPCI_READ_CHECK(8, 4, 0xffffffff);
    VPCI_READ_CHECK(8, 2, 0xffff);
    VPCI_READ_CHECK(8, 1, 0xff);
    VPCI_WRITE(10, 2, 0xbeef);
    VPCI_READ_CHECK(10, 2, 0xffff);

    /* Read of multiple registers */
    VPCI_CHECK_REG(7, 1, 0xbd);
    VPCI_READ_CHECK(4, 4, 0xbdbabaff);

    /* Partial read of a register. */
    VPCI_CHECK_REG(0, 4, 0x1a1b1c1d);
    VPCI_READ_CHECK(2, 1, 0x1b);
    VPCI_READ_CHECK(6, 2, 0xbdba);

    /* Write of multiple registers. */
    VPCI_CHECK_REG(4, 4, 0xaabbccff);

    /* Partial write of a register. */
    VPCI_CHECK_REG(2, 1, 0xfe);
    VPCI_CHECK_REG(6, 2, 0xfebc);

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

