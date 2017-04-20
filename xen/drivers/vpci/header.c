/*
 * Generic functionality for handling accesses to the PCI header from the
 * configuration space.
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

static int vpci_modify_bars(struct pci_dev *pdev, const bool map)
{
    struct vpci_header *header = &pdev->vpci->header;
    unsigned int i;
    int rc = 0;

    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        paddr_t gaddr = map ? header->bars[i].gaddr
                            : header->bars[i].mapped_addr;
        paddr_t paddr = header->bars[i].paddr;
        size_t size = header->bars[i].size;

        if ( header->bars[i].type != VPCI_BAR_MEM &&
             header->bars[i].type != VPCI_BAR_MEM64_LO )
            continue;

        if ( pdev->vpci->msix != NULL && pdev->vpci->msix->bir == i )
        {
            /* There's an MSI-X table inside of this BAR. */
            paddr_t msix_gaddr = gaddr + pdev->vpci->msix->offset;
            paddr_t msix_paddr = paddr + pdev->vpci->msix->offset;
            size_t msix_size = pdev->vpci->msix->max_entries *
                               PCI_MSIX_ENTRY_SIZE;

            ASSERT(IS_ALIGNED(msix_gaddr, PAGE_SIZE) &&
                   IS_ALIGNED(msix_paddr, PAGE_SIZE));

            rc = modify_mmio(pdev->domain, PFN_DOWN(gaddr), PFN_DOWN(paddr),
                             PFN_DOWN(msix_paddr - paddr), map);
            if ( rc )
                break;

            rc = modify_mmio(pdev->domain, PFN_UP(msix_gaddr + msix_size),
                             PFN_UP(msix_paddr + msix_size),
                             PFN_UP(paddr + size -
                                    round_pgup(msix_paddr + msix_size)), map);
            if ( rc )
                break;

            if ( map )
                pdev->vpci->msix->addr = msix_gaddr;
        }
        else
        {
            rc = modify_mmio(pdev->domain, PFN_DOWN(gaddr), PFN_DOWN(paddr),
                             PFN_UP(size), map);
            if ( rc )
                break;
        }

        header->bars[i].mapped_addr = map ? gaddr : 0;
    }

    return rc;
}

static int vpci_cmd_read(struct pci_dev *pdev, unsigned int reg,
                         union vpci_val *val, void *data)
{
    struct vpci_header *header = data;

    val->word = header->command;

    return 0;
}

static int vpci_cmd_write(struct pci_dev *pdev, unsigned int reg,
                          union vpci_val val, void *data)
{
    struct vpci_header *header = data;
    uint16_t new_cmd, saved_cmd;
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    int rc;

    new_cmd = val.word;
    saved_cmd = header->command;

    if ( !((new_cmd ^ saved_cmd) & PCI_COMMAND_MEMORY) )
        goto out;

    /* Memory space access change. */
    rc = vpci_modify_bars(pdev, new_cmd & PCI_COMMAND_MEMORY);
    if ( rc )
    {
        dprintk(XENLOG_ERR,
                "%04x:%02x:%02x.%u:unable to %smap BARs: %d\n",
                seg, bus, slot, func,
                new_cmd & PCI_COMMAND_MEMORY ? "" : "un", rc);
        return rc;
    }

 out:
    pci_conf_write16(seg, bus, slot, func, reg, new_cmd);
    header->command = pci_conf_read16(seg, bus, slot, func, reg);
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
        val->double_word = bar->gaddr >> (hi ? 32 : 0);

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
    bar->gaddr &= hi ? ~GENMASK(63, 32) : ~GENMASK(31, 0);
    wdata &= hi ? GENMASK(31, 0) : PCI_BASE_ADDRESS_MEM_MASK;
    bar->gaddr |= (uint64_t)wdata << (hi ? 32 : 0);

    ASSERT(IS_ALIGNED(bar->gaddr, PAGE_SIZE));

    return 0;
}

static int vpci_init_bars(struct pci_dev *pdev)
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
                               PCI_COMMAND, 2, header);
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

        ASSERT(IS_ALIGNED(addr, PAGE_SIZE));

        /* Initial guest address is the hardware one. */
        bars[i].gaddr = bars[i].paddr = addr;
        bars[i].size = size;
        bars[i].attributes = val & ~PCI_BASE_ADDRESS_MEM_MASK;

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

    if ( header->command & PCI_COMMAND_MEMORY )
    {
        rc = vpci_modify_bars(pdev, true);
        if ( rc )
        {
            dprintk(XENLOG_ERR, "%04x:%02x:%02x.%u: unable to map BARs: %d\n",
                    seg, bus, slot, func, rc);
            return rc;
        }
    }

    return 0;
}

REGISTER_VPCI_INIT(vpci_init_bars, true);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

