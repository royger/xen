/*
 * Generic functionality for handling accesses to the PCI configuration space
 * from guests.
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

#include <xen/sched.h>
#include <xen/vpci.h>

extern const vpci_register_init_t __start_vpci_array[], __end_vpci_array[];
#define NUM_VPCI_INIT (__end_vpci_array - __start_vpci_array)
#define vpci_init __start_vpci_array

int xen_vpci_add_handlers(struct pci_dev *pdev)
{
    int i, rc = 0;

    if ( !has_vpci(pdev->domain) )
        return 0;

    pdev->vpci = xzalloc(struct vpci);
    if ( !pdev->vpci )
        return -ENOMEM;

    pdev->vpci->handlers = RB_ROOT;

    for ( i = 0; i < NUM_VPCI_INIT; i++ )
    {
        rc = vpci_init[i](pdev);
        if ( rc )
            break;
    }

    return rc;
}

/* Internal struct to store the emulated PCI registers. */
struct vpci_register {
    vpci_read_t read;
    vpci_write_t write;
    unsigned int size;
    unsigned int offset;
    void *priv_data;
    struct rb_node node;
};

static bool vpci_register_overlap(const struct vpci_register *r,
                                  unsigned int offset)
{
    if ( offset >= r->offset && offset < r->offset + r->size )
        return true;
    return false;
}


static int vpci_register_cmp(const struct vpci_register *r1,
                             const struct vpci_register *r2)
{
    /* Make sure there's no overlap between registers. */
    if ( vpci_register_overlap(r1, r2->offset) ||
         vpci_register_overlap(r1, r2->offset + r2->size - 1) ||
         vpci_register_overlap(r2, r1->offset) ||
         vpci_register_overlap(r2, r1->offset + r1->size - 1) )
        return 0;

    if (r1->offset < r2->offset)
        return -1;
    else if (r1->offset > r2->offset)
        return 1;

    ASSERT_UNREACHABLE();
    return 0;
}

static struct vpci_register *vpci_find_register(const struct pci_dev *pdev,
                                                unsigned int reg,
                                                unsigned int size)
{
    struct rb_node *node;
    struct vpci_register r = {
        .offset = reg,
        .size = size,
    };

    node = pdev->vpci->handlers.rb_node;
    while ( node )
    {
        struct vpci_register *t =
            container_of(node, struct vpci_register, node);

        switch ( vpci_register_cmp(&r, t) )
        {
        case -1:
            node = node->rb_left;
            break;
        case 1:
            node = node->rb_right;
            break;
        default:
            return t;
        }
    }

    return NULL;
}

int xen_vpci_add_register(struct pci_dev *pdev, vpci_read_t read_handler,
                          vpci_write_t write_handler, unsigned int offset,
                          unsigned int size, void *data)
{
    struct rb_node **new, *parent;
    struct vpci_register *r;

    /* Some sanity checks. */
    if ( size > 4 || size == 3 || offset >= 0xFFF )
        return -EINVAL;

    r = xzalloc(struct vpci_register);
    if ( !r )
        return -ENOMEM;

    r->read = read_handler;
    r->write = write_handler;
    r->size = size;
    r->offset = offset;
    r->priv_data = data;

    new = &pdev->vpci->handlers.rb_node;
    parent = NULL;

    while (*new) {
        struct vpci_register *this =
            container_of(*new, struct vpci_register, node);

        parent = *new;
        switch ( vpci_register_cmp(r, this) )
        {
        case -1:
            new = &((*new)->rb_left);
            break;
        case 1:
            new = &((*new)->rb_right);
            break;
        default:
            xfree(r);
            return -EEXIST;
        }
    }

    rb_link_node(&r->node, parent, new);
    rb_insert_color(&r->node, &pdev->vpci->handlers);

    return 0;
}

int xen_vpci_remove_register(struct pci_dev *pdev, unsigned int offset)
{
    struct vpci_register *r;

    r = vpci_find_register(pdev, offset, 1 /* size doesn't matter here. */);
    if ( !r )
        return -ENOENT;

    rb_erase(&r->node, &pdev->vpci->handlers);
    xfree(r);

    return 0;
}

/* Wrappers for performing reads/writes to the underlying hardware. */
static void vpci_read_hw(unsigned int seg, unsigned int bus,
                         unsigned int devfn, unsigned int reg, uint32_t size,
                         uint32_t *data)
{
    switch ( size )
    {
    case 4:
        *data = pci_conf_read32(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                                reg);
        break;
    case 3:
        /*
         * This is possible because a 4byte read can have 1byte trapped and
         * the rest passed-through.
         */
        *data = pci_conf_read16(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                                reg + 1) << 8;
        *data |= pci_conf_read8(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                               reg);
        break;
    case 2:
        *data = pci_conf_read16(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                                reg);
        break;
    case 1:
        *data = pci_conf_read8(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                               reg);
        break;
    default:
        BUG();
    }
}

static void vpci_write_hw(unsigned int seg, unsigned int bus,
                          unsigned int devfn, unsigned int reg, uint32_t size,
                          uint32_t data)
{
    switch ( size )
    {
    case 4:
        pci_conf_write32(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), reg,
                         data);
        break;
    case 3:
        /*
         * This is possible because a 4byte write can have 1byte trapped and
         * the rest passed-through.
         */
        pci_conf_write8(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), reg, data);
        pci_conf_write16(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), reg + 1,
                         data >> 8);
        break;
    case 2:
        pci_conf_write16(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), reg,
                         data);
        break;
    case 1:
        pci_conf_write8(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), reg, data);
        break;
    default:
        BUG();
    }
}

/* Helper macros for the read/write handlers. */
#define GENMASK_BYTES(e, s) GENMASK((e) * 8, (s) * 8)
#define SHIFT_RIGHT_BYTES(d, o) d >>= (o) * 8
#define ADD_RESULT(r, d, s, o) r |= ((d) & GENMASK_BYTES(s, 0)) << ((o) * 8)

int xen_vpci_read(unsigned int seg, unsigned int bus, unsigned int devfn,
                  unsigned int reg, uint32_t size, uint32_t *data)
{
    struct domain *d = current->domain;
    struct pci_dev *pdev;
    const struct vpci_register *r;
    union vpci_val val = { .double_word = 0 };
    unsigned int data_rshift = 0, data_lshift = 0, data_size;
    uint32_t tmp_data;
    int rc;

    *data = 0;

    /* Find the PCI dev matching the address. */
    pdev = pci_get_pdev_by_domain(d, seg, bus, devfn);
    if ( !pdev )
        goto passthrough;

    /* Find the vPCI register handler. */
    r = vpci_find_register(pdev, reg, size);
    if ( !r )
        goto passthrough;

    if ( r->offset > reg )
    {
        /*
         * There's a heading gap into the emulated register.
         * NB: it's possible for this recursive call to have a size of 3.
         */
        rc = xen_vpci_read(seg, bus, devfn, reg, r->offset - reg, &tmp_data);
        if ( rc )
            return rc;

        /* Add the head read to the partial result. */
        ADD_RESULT(*data, tmp_data, r->offset - reg, 0);
        data_lshift = r->offset - reg;

        /* Account for the read. */
        size -= data_lshift;
        reg += data_lshift;
    }
    else if ( r->offset < reg )
        /* There's an offset into the emulated register */
        data_rshift = reg - r->offset;

    ASSERT(data_lshift == 0 || data_rshift == 0);
    data_size = min(size, r->size - data_rshift);
    ASSERT(data_size != 0);

    /* Perform the read of the register. */
    rc = r->read(pdev, r->offset, &val, r->priv_data);
    if ( rc )
        return rc;

    val.double_word >>= data_rshift * 8;
    ADD_RESULT(*data, val.double_word, data_size, data_lshift);

    /* Account for the read */
    size -= data_size;
    reg += data_size;

    /* Read the remaining, if any. */
    if ( size > 0 )
    {
        /*
         * Read tailing data.
         * NB: it's possible for this recursive call to have a size of 3.
         */
        rc = xen_vpci_read(seg, bus, devfn, reg, size, &tmp_data);
        if ( rc )
            return rc;

        /* Add the tail read to the partial result. */
        ADD_RESULT(*data, tmp_data, size, data_size + data_lshift);
    }

    return 0;

 passthrough:
    vpci_read_hw(seg, bus, devfn, reg, size, data);
    return 0;
}

/* Perform a maybe partial write to a register. */
static int vpci_write_helper(struct pci_dev *pdev,
                             const struct vpci_register *r, unsigned int size,
                             unsigned int offset, uint32_t data)
{
    union vpci_val val = { .double_word = data };
    int rc;

    ASSERT(size <= r->size);
    if ( size != r->size )
    {
        rc = r->read(pdev, r->offset, &val, r->priv_data);
        if ( rc )
            return rc;
        val.double_word &= ~GENMASK_BYTES(size + offset, offset);
        data &= GENMASK_BYTES(size, 0);
        val.double_word |= data << (offset * 8);
    }
    return r->write(pdev, r->offset, val, r->priv_data);
}

int xen_vpci_write(unsigned int seg, unsigned int bus, unsigned int devfn,
                   unsigned int reg, uint32_t size, uint32_t data)
{
    struct domain *d = current->domain;
    struct pci_dev *pdev;
    struct vpci_register *r;
    unsigned int data_size, data_offset = 0;
    int rc;

    /* Find the PCI dev matching the address. */
    pdev = pci_get_pdev_by_domain(d, seg, bus, devfn);
    if ( !pdev )
        goto passthrough;

    /* Find the vPCI register handler. */
    r = vpci_find_register(pdev, reg, size);
    if ( !r )
        goto passthrough;

    else if ( r->offset > reg )
    {
        /*
         * There's a heading gap into the emulated register found.
         * NB: it's possible for this recursive call to have a size of 3.
         */
        rc = xen_vpci_write(seg, bus, devfn, reg, r->offset - reg, data);
        if ( rc )
            return rc;

        /* Advance the data by the written size. */
        SHIFT_RIGHT_BYTES(data, r->offset - reg);
        size -= r->offset - reg;
        reg += r->offset - reg;
    }
    else if ( r->offset < reg )
        /* There's an offset into the emulated register. */
        data_offset = reg - r->offset;

    data_size = min(size, r->size - data_offset);

    /* Perform the write of the register. */
    ASSERT(data_size != 0);
    rc = vpci_write_helper(pdev, r, data_size, data_offset, data);
    if ( rc )
        return rc;

    /* Account for the read */
    size -= data_size;
    reg += data_size;
    SHIFT_RIGHT_BYTES(data, data_size);

    /* Write the remaining, if any. */
    if ( size > 0 )
    {
        /*
         * Write tailing data.
         * NB: it's possible for this recursive call to have a size of 3.
         */
        rc = xen_vpci_write(seg, bus, devfn, reg, size, data);
        if ( rc )
            return rc;
    }

    return 0;

 passthrough:
    vpci_write_hw(seg, bus, devfn, reg, size, data);
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

