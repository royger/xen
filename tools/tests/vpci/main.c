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
static struct vpci vpci;

static struct domain d = {
    .lock = false,
};

struct pci_dev test_pdev = {
    .domain = &d,
    .vpci = &vpci,
};

static struct vcpu v = {
    .domain = &d
};

struct vcpu *current = &v;

/* Dummy hooks, write stores data, read fetches it. */
static void vpci_read8(struct pci_dev *pdev, unsigned int reg,
                       union vpci_val *val, void *data)
{
    uint8_t *priv = data;

    val->u8 = *priv;
}

static void vpci_write8(struct pci_dev *pdev, unsigned int reg,
                        union vpci_val val, void *data)
{
    uint8_t *priv = data;

    *priv = val.u8;
}

static void vpci_read16(struct pci_dev *pdev, unsigned int reg,
                        union vpci_val *val, void *data)
{
    uint16_t *priv = data;

    val->u16 = *priv;
}

static void vpci_write16(struct pci_dev *pdev, unsigned int reg,
                         union vpci_val val, void *data)
{
    uint16_t *priv = data;

    *priv = val.u16;
}

static void vpci_read32(struct pci_dev *pdev, unsigned int reg,
                        union vpci_val *val, void *data)
{
    uint32_t *priv = data;

    val->u32 = *priv;
}

static void vpci_write32(struct pci_dev *pdev, unsigned int reg,
                         union vpci_val val, void *data)
{
    uint32_t *priv = data;

    *priv = val.u32;
}

#define VPCI_READ(reg, size, data) ({                   \
    vpci_lock(&d);                                      \
    data = vpci_read(0, 0, 0, 0, reg, size);            \
    vpci_unlock(&d);                                    \
})

#define VPCI_READ_CHECK(reg, size, expected) ({         \
    uint32_t _val;                                      \
    VPCI_READ(reg, size, _val);                         \
    assert(_val == (expected));                         \
})

#define VPCI_WRITE(reg, size, data) ({                  \
    vpci_lock(&d);                                      \
    vpci_write(0, 0, 0, 0, reg, size, data);            \
    vpci_unlock(&d);                                    \
})

#define VPCI_WRITE_CHECK(reg, size, data) ({            \
    VPCI_WRITE(reg, size, data);                        \
    VPCI_READ_CHECK(reg, size, data);                   \
})

#define VPCI_ADD_REG(fread, fwrite, off, size, store)                       \
    assert(!vpci_add_register(&test_pdev, fread, fwrite, off, size, &store))

#define VPCI_ADD_INVALID_REG(fread, fwrite, off, size)                      \
    assert(vpci_add_register(&test_pdev, fread, fwrite, off, size, NULL))

#define VPCI_REMOVE_REG(off, size)                                          \
    assert(!vpci_remove_register(&test_pdev, off, size))

#define VPCI_REMOVE_INVALID_REG(off, size)                                  \
    assert(vpci_remove_register(&test_pdev, off, size))

/* Read a 32b register using all possible sizes. */
void multiread4(unsigned int reg, uint32_t val)
{
    unsigned int i;

    /* Read using bytes. */
    for ( i = 0; i < 4; i++ )
        VPCI_READ_CHECK(reg + i, 1, (val >> (i * 8)) & UINT8_MAX);

    /* Read using 2bytes. */
    for ( i = 0; i < 2; i++ )
        VPCI_READ_CHECK(reg + i * 2, 2, (val >> (i * 2 * 8)) & UINT16_MAX);

    VPCI_READ_CHECK(reg, 4, val);
}

void multiwrite4_check(unsigned int reg, uint32_t val)
{
    unsigned int i;

    /* Write using bytes. */
    for ( i = 0; i < 4; i++ )
        VPCI_WRITE_CHECK(reg + i, 1, (val >> (i * 8)) & UINT8_MAX);
    multiread4(reg, val);

    /* Write using 2bytes. */
    for ( i = 0; i < 2; i++ )
        VPCI_WRITE_CHECK(reg + i * 2, 2, (val >> (i * 2 * 8)) & UINT16_MAX);
    multiread4(reg, val);

    VPCI_WRITE_CHECK(reg, 4, val);
    multiread4(reg, val);
}

int
main(int argc, char **argv)
{
    /* Index storage by offset. */
    uint32_t r0 = 0xdeadbeef;
    uint8_t r5 = 0xef;
    uint8_t r6 = 0xbe;
    uint8_t r7 = 0xef;
    uint16_t r12 = 0x8696;
    uint8_t r16[4] = { 0 };
    uint16_t r20[2] = { 0 };
    uint32_t r24 = 0;
    uint8_t r28, r30;
    unsigned int i;
    int rc;

    INIT_LIST_HEAD(&vpci.handlers);

    VPCI_ADD_REG(vpci_read32, vpci_write32, 0, 4, r0);
    VPCI_READ_CHECK(0, 4, 0xdeadbeef);
    VPCI_WRITE_CHECK(0, 4, 0xbcbcbcbc);

    VPCI_ADD_REG(vpci_read8, vpci_write8, 5, 1, r5);
    VPCI_READ_CHECK(5, 1, 0xef);
    VPCI_WRITE_CHECK(5, 1, 0xba);

    VPCI_ADD_REG(vpci_read8, vpci_write8, 6, 1, r6);
    VPCI_READ_CHECK(6, 1, 0xbe);
    VPCI_WRITE_CHECK(6, 1, 0xba);

    VPCI_ADD_REG(vpci_read8, vpci_write8, 7, 1, r7);
    VPCI_READ_CHECK(7, 1, 0xef);
    VPCI_WRITE_CHECK(7, 1, 0xbd);

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
    VPCI_ADD_INVALID_REG(NULL, NULL, 8, 2);

    /* Read/write of unset register. */
    VPCI_READ_CHECK(8, 4, 0xffffffff);
    VPCI_READ_CHECK(8, 2, 0xffff);
    VPCI_READ_CHECK(8, 1, 0xff);
    VPCI_WRITE(10, 2, 0xbeef);
    VPCI_READ_CHECK(10, 2, 0xffff);

    /* Read of multiple registers */
    VPCI_WRITE_CHECK(7, 1, 0xbd);
    VPCI_READ_CHECK(4, 4, 0xbdbabaff);

    /* Partial read of a register. */
    VPCI_WRITE_CHECK(0, 4, 0x1a1b1c1d);
    VPCI_READ_CHECK(2, 1, 0x1b);
    VPCI_READ_CHECK(6, 2, 0xbdba);

    /* Write of multiple registers. */
    VPCI_WRITE_CHECK(4, 4, 0xaabbccff);

    /* Partial write of a register. */
    VPCI_WRITE_CHECK(2, 1, 0xfe);
    VPCI_WRITE_CHECK(6, 2, 0xfebc);

    /*
     * Test all possible read/write size combinations.
     *
     * Populate 128bits (16B) with 1B registers, 160bits (20B) with 2B
     * registers, and finally 192bits (24B) with 4B registers.
     *
     * Then perform all possible write and read sizes on each of them.
     *
     *               ...
     * 32     24     16      8      0
     *  +------+------+------+------+
     *  |r16[3]|r16[2]|r16[1]|r16[0]| 16
     *  +------+------+------+------+
     *  |    r20[1]   |    r20[0]   | 20
     *  +-------------+-------------|
     *  |            r24            | 24
     *  +-------------+-------------+
     *
     */
    VPCI_ADD_REG(vpci_read8, vpci_write8, 16, 1, r16[0]);
    VPCI_ADD_REG(vpci_read8, vpci_write8, 17, 1, r16[1]);
    VPCI_ADD_REG(vpci_read8, vpci_write8, 18, 1, r16[2]);
    VPCI_ADD_REG(vpci_read8, vpci_write8, 19, 1, r16[3]);

    VPCI_ADD_REG(vpci_read16, vpci_write16, 20, 2, r20[0]);
    VPCI_ADD_REG(vpci_read16, vpci_write16, 22, 2, r20[1]);

    VPCI_ADD_REG(vpci_read32, vpci_write32, 24, 4, r24);

    /* Check the initial value is 0. */
    multiread4(16, 0);
    multiread4(20, 0);
    multiread4(24, 0);

    multiwrite4_check(16, 0xdeadbeef);
    multiwrite4_check(20, 0xdeadbeef);
    multiwrite4_check(24, 0xdeadbeef);

    /*
     * Check multiple non-consecutive gaps on the same read/write:
     *
     * 32     24     16      8      0
     *  +------+------+------+------+
     *  |\\\\\\|  r30 |\\\\\\|  r28 | 28
     *  +------+------+------+------+
     *
     */
    VPCI_ADD_REG(vpci_read8, vpci_write8, 28, 1, r28);
    VPCI_ADD_REG(vpci_read8, vpci_write8, 30, 1, r30);
    VPCI_WRITE_CHECK(28, 4, 0xffacffdc);

    /* Finally try to remove a couple of registers. */
    VPCI_REMOVE_REG(28, 1);
    VPCI_REMOVE_REG(24, 4);
    VPCI_REMOVE_REG(12, 2);

    VPCI_REMOVE_INVALID_REG(20, 1);
    VPCI_REMOVE_INVALID_REG(16, 2);
    VPCI_REMOVE_INVALID_REG(30, 2);

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

