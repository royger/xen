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
#include <xen/p2m-common.h>

struct vpci_capability {
    struct list_head next;
    uint8_t offset;
    bool masked;
};

static int vpci_cap_read(struct pci_dev *dev, unsigned int reg,
                         union vpci_val *val, void *data)
{
    struct vpci_capability *next, *curr = data;

    val->half_word = 0;
    /* Return the position of the next non-masked capability. */
    while ( (next = list_next_entry(curr, next)) != NULL )
    {
        if ( !next->masked )
        {
            val->half_word = next->offset;
            break;
        }
        curr = next;
    }

    return 0;
}
static int vpci_cap_write(struct pci_dev *dev, unsigned int reg,
                          union vpci_val val, void *data)
{
    /* Ignored. */
    return 0;
}

static int vpci_index_capabilities(struct pci_dev *pdev)
{
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    uint8_t pos = PCI_CAPABILITY_LIST;
    uint16_t status;
    unsigned int max_cap = 48;
    struct vpci_capability *cap;
    int rc;

    INIT_LIST_HEAD(&pdev->vpci->header.cap_list);

    /* Check if device has capabilities. */
    status = pci_conf_read16(seg, bus, slot, func, PCI_STATUS);
    if ( (status & PCI_STATUS_CAP_LIST) == 0 )
        return 0;

    /* Add the root capability pointer. */
    cap = xzalloc(struct vpci_capability);
    if ( !cap )
        return -ENOMEM;

    cap->offset = pos;
    list_add_tail(&cap->next, &pdev->vpci->header.cap_list);
    rc = xen_vpci_add_register(pdev, vpci_cap_read, vpci_cap_write, pos,
                               1, cap);
    if ( rc )
        return rc;

    /*
     * Iterate over the list of capabilities present in the device, and
     * add a handler for each pointer to the next item (PCI_CAP_LIST_NEXT).
     */
    while ( max_cap-- )
    {
        pos = pci_conf_read8(seg, bus, slot, func, pos);
        if ( pos < 0x40 )
            break;

        cap = xzalloc(struct vpci_capability);
        if ( !cap )
            return -ENOMEM;

        cap->offset = pos;
        list_add_tail(&cap->next, &pdev->vpci->header.cap_list);
        pos += PCI_CAP_LIST_NEXT;
        rc = xen_vpci_add_register(pdev, vpci_cap_read, vpci_cap_write, pos,
                                   1, cap);
        if ( rc )
            return rc;
    }

    return 0;
}

static void vpci_mask_capability(struct pci_dev *pdev, uint8_t cap_id)
{
    struct vpci_capability *cap;
    uint8_t cap_offset;

    cap_offset = pci_find_cap_offset(pdev->seg, pdev->bus,
                                     PCI_SLOT(pdev->devfn),
                                     PCI_FUNC(pdev->devfn), cap_id);
    if ( !cap_offset )
        return;

    list_for_each_entry ( cap, &pdev->vpci->header.cap_list, next )
        if ( cap->offset == cap_offset )
            cap->masked = true;
}

static int vpci_cmd_read(struct pci_dev *pdev, unsigned int reg,
                         union vpci_val *val, void *data)
{
    uint16_t *cmd = data;

    val->word = *cmd;
    return 0;
}

static int vpci_cmd_write(struct pci_dev *pdev, unsigned int reg,
                          union vpci_val val, void *data)
{
    uint16_t new_cmd = val.word, *saved_cmd = data;
    struct vpci_bar *bars = pdev->vpci->header.bars;
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    unsigned int i;
    int rc;


    if ( !((new_cmd ^ *saved_cmd) & PCI_COMMAND_MEMORY) )
        goto out;

    /* Memory space access change. */
    for ( i = 0; i < ARRAY_SIZE(pdev->vpci->header.bars); i++ )
    {
        bool map = !!(new_cmd & PCI_COMMAND_MEMORY);

        if ( bars[i].type != VPCI_BAR_MEM &&
             bars[i].type != VPCI_BAR_MEM64_LO )
            continue;

        if ( !map && !bars[i].mapped_addr )
            continue;

        rc = modify_identity_mmio(pdev->domain, PFN_DOWN(bars[i].addr),
                                  PFN_UP(bars[i].size), map);
        if ( rc )
            continue;

        bars[i].mapped_addr = map ? bars[i].addr : 0;
    }

 out:
    pci_conf_write16(seg, bus, slot, func, reg, new_cmd);
    *saved_cmd = pci_conf_read16(seg, bus, slot, func, reg);
    return 0;
}

static int vpci_bar_read(struct pci_dev *pdev, unsigned int reg,
                         union vpci_val *val, void *data)
{
    struct vpci_bar *bar = data;
    bool hi = false;

    ASSERT(bar->type == VPCI_BAR_MEM || bar->type == VPCI_BAR_MEM64_LO ||
           bar->type == VPCI_BAR_MEM64_HI);

    if ( bar->type == VPCI_BAR_MEM64_HI )
    {
        ASSERT(reg - PCI_BASE_ADDRESS_0 > 0);
        bar--;
        hi = true;
    }

    if ( bar->sizing )
        val->double_word = ~(bar->size - 1) >> (hi ? 32 : 0);
    else
        val->double_word = bar->addr >> (hi ? 32 : 0);

    val->double_word |= hi ? 0 : bar->attributes;

    return 0;
}

static int vpci_bar_write(struct pci_dev *pdev, unsigned int reg,
                          union vpci_val val, void *data)
{
    struct vpci_bar *bar = data;
    uint32_t wdata = val.double_word;
    bool hi = false;

    ASSERT(bar->type == VPCI_BAR_MEM || bar->type == VPCI_BAR_MEM64_LO ||
           bar->type == VPCI_BAR_MEM64_HI);

    if ( wdata == GENMASK(31, 0) )
    {
        /* Next reads from this register are going to return the BAR size. */
        bar->sizing = true;
        return 0;
    }

    /* End previous sizing cycle if any. */
    bar->sizing = false;

    if ( bar->type == VPCI_BAR_MEM64_HI )
    {
        ASSERT(reg - PCI_BASE_ADDRESS_0 > 0);
        bar--;
        hi = true;
    }

    /* Update the relevant part of the BAR address. */
    bar->addr &= hi ? ~GENMASK(63, 32) : ~GENMASK(31, 0);
    wdata &= hi ? GENMASK(31, 0) : PCI_BASE_ADDRESS_MEM_MASK;
    bar->addr |= (uint64_t)wdata << (hi ? 32 : 0);

    return 0;
}

static int vpci_index_bars(struct pci_dev *pdev)
{
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    uint8_t header_type;
    unsigned int i, num_bars;
    struct vpci_header *header = &pdev->vpci->header;
    struct vpci_bar *bars = header->bars;
    int rc;

    header_type = pci_conf_read8(seg, bus, slot, func, PCI_HEADER_TYPE) & 0x7f;
    if ( header_type == PCI_HEADER_TYPE_NORMAL )
        num_bars = 6;
    else if ( header_type == PCI_HEADER_TYPE_BRIDGE )
        num_bars = 2;
    else
        return -ENOSYS;

    /* Setup a handler for the control register. */
    header->command = pci_conf_read16(seg, bus, slot, func, PCI_COMMAND);
    rc = xen_vpci_add_register(pdev, vpci_cmd_read, vpci_cmd_write,
                               PCI_COMMAND, 2, &header->command);
    if ( rc )
    {
        dprintk(XENLOG_ERR,
                "%04x:%02x:%02x.%u: failed to add handler register %#x: %d\n",
                seg, bus, slot, func, PCI_COMMAND, rc);
        return rc;
    }


    for ( i = 0; i < num_bars; i++ )
    {
        uint8_t reg = PCI_BASE_ADDRESS_0 + i * 4;
        uint32_t val = pci_conf_read32(seg, bus, slot, func, reg);
        uint64_t addr, size;
        unsigned int index;

        if ( i && bars[i - 1].type == VPCI_BAR_MEM64_LO )
        {
            bars[i].type = VPCI_BAR_MEM64_HI;
            continue;
        }
        else if ( (val & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_IO )
        {
            bars[i].type = VPCI_BAR_IO;
            continue;
        }
        else if ( (val & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
                  PCI_BASE_ADDRESS_MEM_TYPE_64 )
            bars[i].type = VPCI_BAR_MEM64_LO;
        else
            bars[i].type = VPCI_BAR_MEM;

        /* Size the BAR and map it. */
        index = i;
        rc = pci_size_bar(seg, bus, slot, func, PCI_BASE_ADDRESS_0, num_bars,
                          &index, &addr, &size);
        if ( rc )
        {
            dprintk(XENLOG_ERR,
                    "%04x:%02x:%02x.%u: unable to size BAR#%u: %d\n",
                    seg, bus, slot, func, i, rc);
            return rc;
        }

        if ( size == 0 )
        {
            bars[i].type = VPCI_BAR_EMPTY;
            continue;
        }

        bars[i].addr = addr;
        bars[i].size = size;
        bars[i].attributes = val & ~PCI_BASE_ADDRESS_MEM_MASK;

        if ( header->command & PCI_COMMAND_MEMORY)
        {
            /* Memory space accesses are active, map BARs. */
            rc = modify_identity_mmio(pdev->domain, PFN_DOWN(bars[i].addr),
                                      PFN_UP(bars[i].size), true);
            if ( !rc )
                bars[i].mapped_addr = addr;
        }

        rc = xen_vpci_add_register(pdev, vpci_bar_read, vpci_bar_write, reg,
                                   4, &bars[i]);
        if ( rc )
        {
            dprintk(XENLOG_ERR,
                    "%04x:%02x:%02x.%u: failed to add handler for BAR#%u: %d\n",
                    seg, bus, slot, func, i, rc);
            return rc;
        }
    }

    return 0;
}

static int vpci_header_init(struct pci_dev *pdev)
{
    int rc;

    rc = vpci_index_bars(pdev);
    if ( rc )
        return rc;

    rc = vpci_index_capabilities(pdev);
    if ( rc )
        return rc;

    /* Mask MSI and MSI-X capabilities until Xen handles them. */
    vpci_mask_capability(pdev, PCI_CAP_ID_MSI);
    vpci_mask_capability(pdev, PCI_CAP_ID_MSIX);

    return 0;
}

REGISTER_VPCI_INIT(vpci_header_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

