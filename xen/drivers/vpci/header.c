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
#include <asm/p2m.h>

#define MAPPABLE_BAR(x)                                                 \
    (((x)->type == VPCI_BAR_MEM32 || (x)->type == VPCI_BAR_MEM64_LO ||  \
     ((x)->type == VPCI_BAR_ROM && (x)->enabled)) &&                    \
     (x)->addr != INVALID_PADDR)

static struct rangeset *vpci_get_bar_memory(const struct domain *d,
                                            const struct vpci_bar *map)
{
    const struct pci_dev *pdev;
    struct rangeset *mem = rangeset_new(NULL, NULL, 0);
    int rc;

    if ( !mem )
        return ERR_PTR(-ENOMEM);

    /*
     * Create a rangeset that represents the current BAR memory region
     * and compare it against all the currently active BAR memory regions.
     * If an overlap is found, subtract it from the region to be
     * mapped/unmapped.
     *
     * NB: the rangeset uses frames, and if start and end addresses are
     * equal it means only one frame is used, that's why PFN_DOWN is used
     * to calculate the end of the rangeset.
     */
    rc = rangeset_add_range(mem, PFN_DOWN(map->addr),
                            PFN_DOWN(map->addr + map->size));
    if ( rc )
    {
        rangeset_destroy(mem);
        return ERR_PTR(rc);
    }

    list_for_each_entry(pdev, &d->arch.pdev_list, domain_list)
    {
        uint16_t cmd = pci_conf_read16(pdev->seg, pdev->bus,
                                       PCI_SLOT(pdev->devfn),
                                       PCI_FUNC(pdev->devfn),
                                       PCI_COMMAND);
        unsigned int i;

        /* Check if memory decoding is enabled. */
        if ( !(cmd & PCI_COMMAND_MEMORY) )
            continue;

        for ( i = 0; i < ARRAY_SIZE(pdev->vpci->header.bars); i++ )
        {
            const struct vpci_bar *bar = &pdev->vpci->header.bars[i];

            if ( bar == map || !MAPPABLE_BAR(bar) ||
                 !rangeset_overlaps_range(mem, PFN_DOWN(bar->addr),
                                          PFN_DOWN(bar->addr + bar->size)) )
                continue;

            rc = rangeset_remove_range(mem, PFN_DOWN(bar->addr),
                                       PFN_DOWN(bar->addr + bar->size));
            if ( rc )
            {
                rangeset_destroy(mem);
                return ERR_PTR(rc);
            }
        }
    }

    return mem;
}

struct map_data {
    struct domain *d;
    bool map;
};

static int vpci_map_range(unsigned long s, unsigned long e, void *data)
{
    const struct map_data *map = data;

    return modify_mmio(map->d, _gfn(s), _mfn(s), e - s + 1, map->map);
}

static int vpci_unmap_msix(struct domain *d, struct vpci_msix_mem *msix)
{
    unsigned long gfn;

    for ( gfn = PFN_DOWN(msix->addr); gfn <= PFN_UP(msix->addr + msix->size);
          gfn++ )
    {
        p2m_type_t t;
        mfn_t mfn = get_gfn(d, gfn, &t);
        int rc;

        if ( mfn_eq(mfn, INVALID_MFN) )
        {
            /* Nothing to do, this is already a hole. */
            put_gfn(d, gfn);
            continue;
        }

        if ( !p2m_is_mmio(t) )
        {
            put_gfn(d, gfn);
            return -EINVAL;
        }

        rc = modify_mmio(d, _gfn(gfn), mfn, 1, false);
        put_gfn(d, gfn);
        if ( rc )
            return rc;
    }

    return 0;
}

static int vpci_modify_bar(struct domain *d, const struct vpci_bar *bar,
                           const bool map)
{
    struct rangeset *mem;
    struct map_data data = { .d = d, .map = map };
    unsigned int i;
    int rc;

    ASSERT(MAPPABLE_BAR(bar));

    mem = vpci_get_bar_memory(d, bar);
    if ( IS_ERR(mem) )
        return -PTR_ERR(mem);

    /*
     * Make sure the MSI-X regions of the BAR are not mapped into the domain
     * p2m, or else the MSI-X handlers are useless. Only do this when mapping,
     * since that's when the memory decoding on the device is enabled.
     */
    for ( i = 0; i < ARRAY_SIZE(bar->msix); i++ )
    {
        struct vpci_msix_mem *msix = bar->msix[i];

        if ( !msix || msix->addr == INVALID_PADDR )
            continue;

        if ( map )
        {
            rc = vpci_unmap_msix(d, msix);
            if ( rc )
            {
                rangeset_destroy(mem);
                return rc;
            }
        }

        rc = rangeset_remove_range(mem, PFN_DOWN(msix->addr),
                                   PFN_DOWN(msix->addr + msix->size));
        if ( rc )
        {
            rangeset_destroy(mem);
            return rc;
        }

    }

    rc = rangeset_report_ranges(mem, 0, ~0ul, vpci_map_range, &data);
    rangeset_destroy(mem);
    if ( rc )
        return rc;

    return 0;
}

static int vpci_modify_bars(const struct pci_dev *pdev, const bool map)
{
    const struct vpci_header *header = &pdev->vpci->header;
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        const struct vpci_bar *bar = &header->bars[i];
        int rc;

        if ( !MAPPABLE_BAR(bar) )
            continue;

        rc = vpci_modify_bar(pdev->domain, bar, map);
        if ( rc )
            return rc;
    }

    return 0;
}

static void vpci_cmd_read(struct pci_dev *pdev, unsigned int reg,
                          union vpci_val *val, void *data)
{
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);

    val->u16 = pci_conf_read16(seg, bus, slot, func, reg);
}

static void vpci_cmd_write(struct pci_dev *pdev, unsigned int reg,
                           union vpci_val val, void *data)
{
    uint16_t cmd = val.u16, current_cmd;
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    int rc;

    current_cmd = pci_conf_read16(seg, bus, slot, func, reg);

    if ( !((cmd ^ current_cmd) & PCI_COMMAND_MEMORY) )
    {
        /*
         * Let the guest play with all the bits directly except for the
         * memory decoding one.
         */
        pci_conf_write16(seg, bus, slot, func, reg, cmd);
        return;
    }

    /* Memory space access change. */
    rc = vpci_modify_bars(pdev, cmd & PCI_COMMAND_MEMORY);
    if ( rc )
    {
        dprintk(XENLOG_ERR,
                "%04x:%02x:%02x.%u:unable to %smap BARs: %d\n",
                seg, bus, slot, func,
                cmd & PCI_COMMAND_MEMORY ? "" : "un", rc);
        return;
    }

    pci_conf_write16(seg, bus, slot, func, reg, cmd);
}

static void vpci_bar_read(struct pci_dev *pdev, unsigned int reg,
                          union vpci_val *val, void *data)
{
    const struct vpci_bar *bar = data;
    bool hi = false;

    ASSERT(bar->type == VPCI_BAR_MEM32 || bar->type == VPCI_BAR_MEM64_LO ||
           bar->type == VPCI_BAR_MEM64_HI);

    if ( bar->type == VPCI_BAR_MEM64_HI )
    {
        ASSERT(reg > PCI_BASE_ADDRESS_0);
        bar--;
        hi = true;
    }

    if ( bar->sizing )
        val->u32 = ~(bar->size - 1) >> (hi ? 32 : 0);
    else
        val->u32 = bar->addr >> (hi ? 32 : 0);

    if ( !hi )
    {
        val->u32 |= bar->type == VPCI_BAR_MEM32 ? PCI_BASE_ADDRESS_MEM_TYPE_32
                                                : PCI_BASE_ADDRESS_MEM_TYPE_64;
        val->u32 |= bar->prefetchable ? PCI_BASE_ADDRESS_MEM_PREFETCH : 0;
    }
}

static void vpci_bar_write(struct pci_dev *pdev, unsigned int reg,
                           union vpci_val val, void *data)
{
    struct vpci_bar *bar = data;
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    uint32_t wdata = val.u32, size_mask;
    unsigned int i;
    bool hi = false;

    switch ( bar->type )
    {
    case VPCI_BAR_MEM32:
    case VPCI_BAR_MEM64_LO:
        size_mask = (uint32_t)PCI_BASE_ADDRESS_MEM_MASK;
        break;
    case VPCI_BAR_MEM64_HI:
        size_mask = ~0u;
        break;
    default:
        ASSERT_UNREACHABLE();
        return;
    }

    if ( (wdata & size_mask) == size_mask )
    {
        /* Next reads from this register are going to return the BAR size. */
        bar->sizing = true;
        return;
    }

    /* End previous sizing cycle if any. */
    bar->sizing = false;

    /*
     * Ignore attempts to change the position of the BAR if memory decoding is
     * active.
     */
    if ( pci_conf_read16(seg, bus, slot, func, PCI_COMMAND) &
         PCI_COMMAND_MEMORY )
        return;

    if ( bar->type == VPCI_BAR_MEM64_HI )
    {
        ASSERT(reg > PCI_BASE_ADDRESS_0);
        bar--;
        hi = true;
    }

    if ( !hi )
        wdata &= PCI_BASE_ADDRESS_MEM_MASK;

    /* Update the relevant part of the BAR address. */
    bar->addr &= ~((uint64_t)0xffffffff << (hi ? 32 : 0));
    bar->addr |= (uint64_t)wdata << (hi ? 32 : 0);

    /* Update any MSI-X areas contained in this BAR. */
    for ( i = 0; i < ARRAY_SIZE(bar->msix); i++ )
        if ( bar->msix[i] )
            bar->msix[i]->addr = bar->addr + bar->msix[i]->offset;

    /* Make sure Xen writes back the same value for the BAR RO bits. */
    if ( !hi )
        wdata |= pci_conf_read32(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                                 PCI_FUNC(pdev->devfn), reg) &
                                 ~PCI_BASE_ADDRESS_MEM_MASK;
    pci_conf_write32(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                     PCI_FUNC(pdev->devfn), reg, wdata);
}

static void vpci_rom_read(struct pci_dev *pdev, unsigned int reg,
                          union vpci_val *val, void *data)
{
    const struct vpci_bar *rom = data;

    if ( rom->sizing )
        val->u32 = ~(rom->size - 1);
    else
        val->u32 = rom->addr;

    val->u32 |= rom->enabled ? PCI_ROM_ADDRESS_ENABLE : 0;
}

static void vpci_rom_write(struct pci_dev *pdev, unsigned int reg,
                           union vpci_val val, void *data)
{
    struct vpci_bar *rom = data;
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    const uint32_t wdata = val.u32;

    if ( (wdata & PCI_ROM_ADDRESS_MASK) == PCI_ROM_ADDRESS_MASK )
    {
        /* Next reads from this register are going to return the BAR size. */
        rom->sizing = true;
        return;
    }

    /* End previous sizing cycle if any. */
    rom->sizing = false;

    rom->addr = wdata & PCI_ROM_ADDRESS_MASK;

    /* Check if memory decoding is enabled. */
    if ( pci_conf_read16(seg, bus, slot, func, PCI_COMMAND) &
         PCI_COMMAND_MEMORY &&
         (rom->enabled ^ (wdata & PCI_ROM_ADDRESS_ENABLE)) )
    {
        if ( vpci_modify_bar(pdev->domain, rom,
                             wdata & PCI_ROM_ADDRESS_ENABLE) )
            return;

        rom->enabled = wdata & PCI_ROM_ADDRESS_ENABLE;
    }

    pci_conf_write32(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                     PCI_FUNC(pdev->devfn), reg, wdata);
}

static int vpci_init_bars(struct pci_dev *pdev)
{
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    uint8_t header_type;
    uint16_t cmd;
    uint32_t rom_val;
    uint64_t addr, size;
    unsigned int i, num_bars, rom_reg;
    struct vpci_header *header = &pdev->vpci->header;
    struct vpci_bar *bars = header->bars;
    int rc;

    header_type = pci_conf_read8(seg, bus, slot, func, PCI_HEADER_TYPE) & 0x7f;
    switch ( header_type )
    {
    case PCI_HEADER_TYPE_NORMAL:
        num_bars = 6;
        rom_reg = PCI_ROM_ADDRESS;
        break;
    case PCI_HEADER_TYPE_BRIDGE:
        num_bars = 2;
        rom_reg = PCI_ROM_ADDRESS1;
        break;
    default:
        return -EOPNOTSUPP;
    }

    /* Setup a handler for the command register. */
    cmd = pci_conf_read16(seg, bus, slot, func, PCI_COMMAND);
    rc = vpci_add_register(pdev, vpci_cmd_read, vpci_cmd_write, PCI_COMMAND,
                           2, header);
    if ( rc )
        return rc;

    /* Disable memory decoding before sizing. */
    if ( cmd & PCI_COMMAND_MEMORY )
        pci_conf_write16(seg, bus, slot, func, PCI_COMMAND,
                         cmd & ~PCI_COMMAND_MEMORY);

    for ( i = 0; i < num_bars; i++ )
    {
        uint8_t reg = PCI_BASE_ADDRESS_0 + i * 4;
        uint32_t val = pci_conf_read32(seg, bus, slot, func, reg);

        if ( i && bars[i - 1].type == VPCI_BAR_MEM64_LO )
        {
            bars[i].type = VPCI_BAR_MEM64_HI;
            rc = vpci_add_register(pdev, vpci_bar_read, vpci_bar_write, reg, 4,
                                   &bars[i]);
            if ( rc )
                return rc;

            continue;
        }
        if ( (val & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_IO )
        {
            bars[i].type = VPCI_BAR_IO;
            continue;
        }
        if ( (val & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
             PCI_BASE_ADDRESS_MEM_TYPE_64 )
            bars[i].type = VPCI_BAR_MEM64_LO;
        else
            bars[i].type = VPCI_BAR_MEM32;

        /* Size the BAR and map it. */
        rc = pci_size_mem_bar(seg, bus, slot, func, reg, i == num_bars - 1,
                              &addr, &size);
        if ( rc < 0 )
            return rc;

        if ( size == 0 )
        {
            bars[i].type = VPCI_BAR_EMPTY;
            continue;
        }

        if ( cmd & PCI_COMMAND_MEMORY )
        {
            unsigned int j;

            bars[i].addr = addr;

            for ( j = 0; j < ARRAY_SIZE(bars[i].msix); j++ )
                if ( bars[i].msix[j] )
                    bars[i].msix[j]->addr = bars[i].addr +
                                            bars[i].msix[j]->offset;
        }
        else
            bars[i].addr = INVALID_PADDR;

        bars[i].size = size;
        bars[i].prefetchable = val & PCI_BASE_ADDRESS_MEM_PREFETCH;

        rc = vpci_add_register(pdev, vpci_bar_read, vpci_bar_write, reg, 4,
                               &bars[i]);
        if ( rc )
            return rc;
    }

    /* Check expansion ROM. */
    rom_val = pci_conf_read32(seg, bus, slot, func, rom_reg);
    if ( rom_val & PCI_ROM_ADDRESS_ENABLE )
        pci_conf_write32(seg, bus, slot, func, rom_reg,
                         rom_val & ~PCI_ROM_ADDRESS_ENABLE);

    rc = pci_size_mem_bar(seg, bus, slot, func, rom_reg, true, &addr, &size);
    if ( rc < 0 )
        return rc;

    if ( size )
    {
        struct vpci_bar *rom = &header->bars[num_bars];

        rom->type = VPCI_BAR_ROM;
        rom->size = size;
        rom->enabled = rom_val & PCI_ROM_ADDRESS_ENABLE;
        if ( rom->enabled )
            rom->addr = addr;
        else
            rom->addr = INVALID_PADDR;

        rc = vpci_add_register(pdev, vpci_rom_read, vpci_rom_write, rom_reg, 4,
                               rom);
        if ( rc )
            return rc;

        if ( rom->enabled )
            pci_conf_write32(seg, bus, slot, func, rom_reg, rom_val);
    }

    if ( cmd & PCI_COMMAND_MEMORY )
    {
        rc = vpci_modify_bars(pdev, true);
        if ( rc )
            return rc;

        /* Enable memory decoding. */
        pci_conf_write16(seg, bus, slot, func, PCI_COMMAND, cmd);
    }

    return 0;
}

REGISTER_VPCI_INIT(vpci_init_bars, VPCI_PRIORITY_LOW);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

