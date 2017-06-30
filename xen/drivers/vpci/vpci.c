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

/* Internal struct to store the emulated PCI registers. */
struct vpci_register {
    vpci_read_t *read;
    vpci_write_t *write;
    unsigned int size;
    unsigned int offset;
    void *private;
    struct list_head node;
};

int vpci_add_handlers(struct pci_dev *pdev)
{
    unsigned int i;
    int rc = 0;

    if ( !has_vpci(pdev->domain) || pdev->vpci )
        return 0;

    pdev->vpci = xzalloc(struct vpci);
    if ( !pdev->vpci )
        return -ENOMEM;

    INIT_LIST_HEAD(&pdev->vpci->handlers);

    for ( i = 0; i < NUM_VPCI_INIT; i++ )
    {
        rc = __start_vpci_array[i](pdev);
        if ( rc )
            break;
    }

    if ( rc )
    {
        while ( !list_empty(&pdev->vpci->handlers) )
        {
            struct vpci_register *r = list_first_entry(&pdev->vpci->handlers,
                                                       struct vpci_register,
                                                       node);

            list_del(&r->node);
            xfree(r);
        }
        xfree(pdev->vpci);
    }

    return rc;
}

static int vpci_register_cmp(const struct vpci_register *r1,
                             const struct vpci_register *r2)
{
    /* Return 0 if registers overlap. */
    if ( r1->offset < r2->offset + r2->size &&
         r2->offset < r1->offset + r1->size )
        return 0;
    if ( r1->offset < r2->offset )
        return -1;
    if ( r1->offset > r2->offset )
        return 1;

    ASSERT_UNREACHABLE();
    return 0;
}

/* Dummy hooks, writes are ignored, reads return 1's */
static void vpci_ignored_read(struct pci_dev *pdev, unsigned int reg,
                              union vpci_val *val, void *data)
{
    val->u32 = ~(uint32_t)0;
}

static void vpci_ignored_write(struct pci_dev *pdev, unsigned int reg,
                               union vpci_val val, void *data)
{
}

int vpci_add_register(const struct pci_dev *pdev, vpci_read_t read_handler,
                      vpci_write_t write_handler, unsigned int offset,
                      unsigned int size, void *data)
{
    struct list_head *head;
    struct vpci_register *r;

    /* Some sanity checks. */
    if ( (size != 1 && size != 2 && size != 4) ||
         offset >= PCI_CFG_SPACE_EXP_SIZE || offset & (size - 1) ||
         (read_handler == NULL && write_handler == NULL) )
        return -EINVAL;

    r = xmalloc(struct vpci_register);
    if ( !r )
        return -ENOMEM;

    r->read = read_handler ?: vpci_ignored_read;
    r->write = write_handler ?: vpci_ignored_write;
    r->size = size;
    r->offset = offset;
    r->private = data;

    vpci_lock(pdev->domain);

    /* The list of handlers must be keep sorted at all times. */
    list_for_each ( head, &pdev->vpci->handlers )
    {
        const struct vpci_register *this =
            list_entry(head, const struct vpci_register, node);
        int cmp = vpci_register_cmp(r, this);

        if ( cmp < 0 )
            break;
        if ( cmp == 0 )
        {
            vpci_unlock(pdev->domain);
            xfree(r);
            return -EEXIST;
        }
    }

    list_add_tail(&r->node, head);
    vpci_unlock(pdev->domain);

    return 0;
}

int vpci_remove_register(const struct pci_dev *pdev, unsigned int offset,
                         unsigned int size)
{
    const struct vpci_register r = { .offset = offset, .size = size };
    struct vpci_register *rm = NULL;

    vpci_lock(pdev->domain);

    list_for_each_entry ( rm, &pdev->vpci->handlers, node )
        if ( vpci_register_cmp(&r, rm) <= 0 )
            break;

    if ( !rm || rm->offset != offset || rm->size != size )
    {
        vpci_unlock(pdev->domain);
        return -ENOENT;
    }

    list_del(&rm->node);
    vpci_unlock(pdev->domain);
    xfree(rm);

    return 0;
}

/* Wrappers for performing reads/writes to the underlying hardware. */
static uint32_t vpci_read_hw(unsigned int seg, unsigned int bus,
                             unsigned int slot, unsigned int func,
                             unsigned int reg, uint32_t size)
{
    uint32_t data;

    switch ( size )
    {
    case 4:
        data = pci_conf_read32(seg, bus, slot, func, reg);
        break;
    case 2:
        data = pci_conf_read16(seg, bus, slot, func, reg);
        break;
    case 1:
        data = pci_conf_read8(seg, bus, slot, func, reg);
        break;
    default:
        BUG();
    }

    return data;
}

static void vpci_write_hw(unsigned int seg, unsigned int bus,
                          unsigned int slot, unsigned int func,
                          unsigned int reg, uint32_t size, uint32_t data)
{
    switch ( size )
    {
    case 4:
        pci_conf_write32(seg, bus, slot, func, reg, data);
        break;
    case 3:
        /*
         * This is possible because a 4byte write can have 1byte trapped and
         * the rest passed-through.
         */
        if ( reg & 1 )
        {
            pci_conf_write8(seg, bus, slot, func, reg, data);
            pci_conf_write16(seg, bus, slot, func, reg + 1, data >> 8);
        }
        else
        {
            pci_conf_write16(seg, bus, slot, func, reg, data);
            pci_conf_write8(seg, bus, slot, func, reg + 2, data >> 16);
        }
        break;
    case 2:
        pci_conf_write16(seg, bus, slot, func, reg, data);
        break;
    case 1:
        pci_conf_write8(seg, bus, slot, func, reg, data);
        break;
    default:
        BUG();
    }
}

/*
 * Merge new data into a partial result.
 *
 * Zero the bytes of 'data' from [offset, offset + size), and
 * merge the value found in 'new' from [0, offset) left shifted
 * by 'offset'.
 */
uint32_t merge_result(uint32_t data, uint32_t new, unsigned int size,
                      unsigned int offset)
{
    uint32_t mask = ((uint64_t)1 << (size * 8)) - 1;

    return (data & ~(mask << (offset * 8))) | ((new & mask) << (offset * 8));
}

uint32_t vpci_read(unsigned int seg, unsigned int bus, unsigned int slot,
                   unsigned int func, unsigned int reg, uint32_t size)
{
    struct domain *d = current->domain;
    struct pci_dev *pdev;
    const struct vpci_register *r;
    unsigned int data_offset = 0;
    uint32_t data;

    ASSERT(pcidevs_locked());
    ASSERT(vpci_locked(d));

    /*
     * Read the hardware value.
     * NB: at the moment vPCI passthroughs everything (ie: permissive).
     */
    data = vpci_read_hw(seg, bus, slot, func, reg, size);

    /* Find the PCI dev matching the address. */
    pdev = pci_get_pdev_by_domain(d, seg, bus, PCI_DEVFN(slot, func));
    if ( !pdev )
        return data;

    /* Replace any values reported by the emulated registers. */
    list_for_each_entry ( r, &pdev->vpci->handlers, node )
    {
        const struct vpci_register emu = {
            .offset = reg + data_offset,
            .size = size - data_offset
        };
        int cmp = vpci_register_cmp(&emu, r);
        union vpci_val val = { .u32 = ~0 };
        unsigned int merge_size;

        if ( cmp < 0 )
            break;
        if ( cmp > 0 )
            continue;

        r->read(pdev, r->offset, &val, r->private);

        /* Check if the read is in the middle of a register. */
        if ( r->offset < emu.offset )
            val.u32 >>= (emu.offset - r->offset) * 8;

        data_offset = max(emu.offset, r->offset) - reg;
        /* Find the intersection size between the two sets. */
        merge_size = min(emu.offset + emu.size, r->offset + r->size) -
                     max(emu.offset, r->offset);
        /* Merge the emulated data into the native read value. */
        data = merge_result(data, val.u32, merge_size, data_offset);
        data_offset += merge_size;
        if ( data_offset == size )
            break;
    }

    return data;
}

/*
 * Perform a maybe partial write to a register.
 *
 * Note that this will only work for simple registers, if Xen needs to
 * trap accesses to rw1c registers (like the status PCI header register)
 * the logic in vpci_write will have to be expanded in order to correctly
 * deal with them.
 */
static void vpci_write_helper(struct pci_dev *pdev,
                              const struct vpci_register *r, unsigned int size,
                              unsigned int offset, uint32_t data)
{
    union vpci_val val = { .u32 = data };

    ASSERT(size <= r->size);
    if ( size != r->size )
    {
        r->read(pdev, r->offset, &val, r->private);
        val.u32 = merge_result(val.u32, data, size, offset);
    }

    r->write(pdev, r->offset, val, r->private);
}

void vpci_write(unsigned int seg, unsigned int bus, unsigned int slot,
                unsigned int func, unsigned int reg, uint32_t size,
                uint32_t data)
{
    struct domain *d = current->domain;
    struct pci_dev *pdev;
    const struct vpci_register *r;
    unsigned int data_offset = 0;

    ASSERT(pcidevs_locked());
    ASSERT(vpci_locked(d));

    /*
     * Find the PCI dev matching the address.
     * Passthrough everything that's not trapped.
     * */
    pdev = pci_get_pdev_by_domain(d, seg, bus, PCI_DEVFN(slot, func));
    if ( !pdev )
    {
        vpci_write_hw(seg, bus, slot, func, reg, size, data);
        return;
    }

    /* Write the value to the hardware or emulated registers. */
    list_for_each_entry ( r, &pdev->vpci->handlers, node )
    {
        const struct vpci_register emu = {
            .offset = reg + data_offset,
            .size = size - data_offset
        };
        int cmp = vpci_register_cmp(&emu, r);
        unsigned int write_size;

        if ( cmp < 0 )
            break;
        if ( cmp > 0 )
            continue;

        if ( emu.offset < r->offset )
        {
            /* Heading gap, write partial content to hardware. */
            vpci_write_hw(seg, bus, slot, func, emu.offset,
                          r->offset - emu.offset, data >> (data_offset * 8));
            data_offset += r->offset - emu.offset;
        }

        /* Find the intersection size between the two sets. */
        write_size = min(emu.offset + emu.size, r->offset + r->size) -
                     max(emu.offset, r->offset);
        vpci_write_helper(pdev, r, write_size, reg + data_offset - r->offset,
                          data >> (data_offset * 8));
        data_offset += write_size;
        if ( data_offset == size )
            break;
    }

    if ( data_offset < size )
        /* Tailing gap, write the remaining. */
        vpci_write_hw(seg, bus, slot, func, reg + data_offset,
                      size - data_offset, data >> (data_offset * 8));
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

