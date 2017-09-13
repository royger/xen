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

#define MAPPABLE_BAR(x)                                                 \
    ((x)->type == VPCI_BAR_MEM32 || (x)->type == VPCI_BAR_MEM64_LO ||   \
     (x)->type == VPCI_BAR_ROM)

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
     * NB: the rangeset uses inclusive frame numbers.
     */
    rc = rangeset_add_range(mem, PFN_DOWN(map->addr),
                            PFN_DOWN(map->addr + map->size - 1));
    if ( rc )
    {
        rangeset_destroy(mem);
        return ERR_PTR(rc);
    }

    list_for_each_entry(pdev, &d->arch.pdev_list, domain_list)
    {
        unsigned int i;

        for ( i = 0; i < ARRAY_SIZE(pdev->vpci->header.bars); i++ )
        {
            const struct vpci_bar *bar = &pdev->vpci->header.bars[i];
            unsigned long start = PFN_DOWN(bar->addr);
            unsigned long end = PFN_DOWN(bar->addr + bar->size - 1);

            if ( bar == map || !bar->enabled || !MAPPABLE_BAR(bar) ||
                 !rangeset_overlaps_range(mem, start, end) )
                continue;

            rc = rangeset_remove_range(mem, start, end);
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

static int vpci_modify_bar(struct domain *d, const struct vpci_bar *bar,
                           bool map)
{
    struct rangeset *mem;
    struct map_data data = { .d = d, .map = map };
    int rc;

    ASSERT(MAPPABLE_BAR(bar));

    mem = vpci_get_bar_memory(d, bar);
    if ( IS_ERR(mem) )
        return PTR_ERR(mem);

    rc = rangeset_report_ranges(mem, 0, ~0ul, vpci_map_range, &data);
    rangeset_destroy(mem);

    return rc;
}

static int vpci_modify_bars(const struct pci_dev *pdev, bool map)
{
    struct vpci_header *header = &pdev->vpci->header;
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        struct vpci_bar *bar = &header->bars[i];
        int rc;

        if ( !MAPPABLE_BAR(bar) ||
             (bar->type == VPCI_BAR_ROM && !bar->rom_enabled) )
            continue;

        rc = vpci_modify_bar(pdev->domain, bar, map);
        if ( rc )
            return rc;

        bar->enabled = map;
    }

    return 0;
}

static uint32_t vpci_cmd_read(const struct pci_dev *pdev, unsigned int reg,
                              void *data)
{
    return pci_conf_read16(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                           PCI_FUNC(pdev->devfn), reg);
}

static void vpci_cmd_write(const struct pci_dev *pdev, unsigned int reg,
                           uint32_t cmd, void *data)
{
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    uint16_t current_cmd = pci_conf_read16(seg, bus, slot, func, reg);

    /*
     * Let the guest play with all the bits directly except for the
     * memory decoding one.
     */
    if ( (cmd ^ current_cmd) & PCI_COMMAND_MEMORY )
    {
        /* Memory space access change. */
        int rc = vpci_modify_bars(pdev, cmd & PCI_COMMAND_MEMORY);

        if ( rc )
        {
            gprintk(XENLOG_WARNING,
                    "%04x:%02x:%02x.%u:unable to %smap BARs: %d\n",
                    seg, bus, slot, func,
                    cmd & PCI_COMMAND_MEMORY ? "" : "un", rc);
            /*
             * Make sure memory decoding is disabled if BAR mapping/unmapping
             * failed.
             */
            cmd &= ~PCI_COMMAND_MEMORY;
        }
    }

    pci_conf_write16(seg, bus, slot, func, reg, cmd);
}

static uint32_t vpci_bar_fixed_bits(const struct vpci_bar *bar)
{
    return (bar->type == VPCI_BAR_MEM32 ? PCI_BASE_ADDRESS_MEM_TYPE_32
                                        : PCI_BASE_ADDRESS_MEM_TYPE_64) |
           (bar->prefetchable ? PCI_BASE_ADDRESS_MEM_PREFETCH : 0);

}

static uint32_t vpci_bar_read(const struct pci_dev *pdev, unsigned int reg,
                              void *data)
{
    const struct vpci_bar *bar = data;
    uint32_t val;
    bool hi = false;

    ASSERT(bar->type == VPCI_BAR_MEM32 || bar->type == VPCI_BAR_MEM64_LO ||
           bar->type == VPCI_BAR_MEM64_HI);

    if ( bar->type == VPCI_BAR_MEM64_HI )
    {
        ASSERT(reg > PCI_BASE_ADDRESS_0);
        bar--;
        hi = true;
    }

    if ( (hi && bar->sizing_hi) || (!hi && bar->sizing_lo) )
        val = -bar->size >> (hi ? 32 : 0);
    else
        val = bar->addr >> (hi ? 32 : 0);

    val |= hi ? 0 : vpci_bar_fixed_bits(bar);

    return val;
}

static void vpci_bar_write(const struct pci_dev *pdev, unsigned int reg,
                           uint32_t val, void *data)
{
    struct vpci_bar *bar = data;
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    bool hi = false, *sizing;

    if ( pci_conf_read16(seg, bus, slot, func, PCI_COMMAND) &
         PCI_COMMAND_MEMORY )
    {
         gprintk(XENLOG_WARNING,
                 "%04x:%02x:%02x.%u: ignored BAR write with memory decoding enabled\n",
                 seg, bus, slot, func);
        return;
    }

    if ( bar->type == VPCI_BAR_MEM64_HI )
    {
        ASSERT(reg > PCI_BASE_ADDRESS_0);
        bar--;
        hi = true;
        sizing = &bar->sizing_hi;
    }
    else
    {
        val &= PCI_BASE_ADDRESS_MEM_MASK;
        sizing = &bar->sizing_lo;
    }

    /*
     * The PCI Local Bus Specification suggests writing ~0 to both the high
     * and the low part of the BAR registers before attempting to read back
     * the size.
     *
     * However real device BARs registers (at least the ones I've tried)
     * will return the size of the BAR just by having written ~0 to one half
     * of it, independently of the value of the other half of the register.
     * Hence here Xen will switch to returning the size as soon as one half
     * of the BAR register has been written with ~0.
     */
    if ( val == (hi ? 0xffffffff : (uint32_t)PCI_BASE_ADDRESS_MEM_MASK) )
    {
        *sizing = true;
        return;
    }
    *sizing = false;

    /* Update the relevant part of the BAR address. */
    bar->addr &= ~(0xffffffffull << (hi ? 32 : 0));
    bar->addr |= (uint64_t)val << (hi ? 32 : 0);

    /* Make sure Xen writes back the same value for the BAR RO bits. */
    val |= !hi ? 0 : vpci_bar_fixed_bits(bar);

    pci_conf_write32(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                     PCI_FUNC(pdev->devfn), reg, val);
}

static uint32_t vpci_rom_read(const struct pci_dev *pdev, unsigned int reg,
                              void *data)
{
    const struct vpci_bar *rom = data;
    uint32_t val;

    val = rom->sizing_lo ? -rom->size : rom->addr;
    val |= rom->rom_enabled ? PCI_ROM_ADDRESS_ENABLE : 0;

    return val;
}

static void vpci_rom_write(const struct pci_dev *pdev, unsigned int reg,
                           uint32_t val, void *data)
{
    struct vpci_bar *rom = data;
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    uint16_t cmd = pci_conf_read16(seg, bus, slot, func, PCI_COMMAND);
    uint32_t addr = val & PCI_ROM_ADDRESS_MASK;

    if ( pci_conf_read16(seg, bus, slot, func, PCI_COMMAND) &
         PCI_COMMAND_MEMORY && rom->rom_enabled )
    {
         gprintk(XENLOG_WARNING,
                 "%04x:%02x:%02x.%u: ignored ROM BAR write with memory decoding enabled\n",
                 seg, bus, slot, func);
        return;
    }

    if ( addr == (uint32_t)PCI_ROM_ADDRESS_MASK )
    {
        rom->sizing_lo = true;
        return;
    }
    rom->sizing_lo = false;

    rom->addr = addr;

    /* Check if ROM BAR should be mapped. */
    if ( (cmd & PCI_COMMAND_MEMORY) &&
         rom->enabled != !!(val & PCI_ROM_ADDRESS_ENABLE) &&
         vpci_modify_bar(pdev->domain, rom, val & PCI_ROM_ADDRESS_ENABLE) )
        return;

    rom->rom_enabled = val & PCI_ROM_ADDRESS_ENABLE;
    pci_conf_write32(pdev->seg, pdev->bus, slot, func, reg, val);
}

static int vpci_init_bars(struct pci_dev *pdev)
{
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    uint16_t cmd;
    uint64_t addr, size;
    unsigned int i, num_bars, rom_reg;
    struct vpci_header *header = &pdev->vpci->header;
    struct vpci_bar *bars = header->bars;
    int rc;

    switch ( pci_conf_read8(seg, bus, slot, func, PCI_HEADER_TYPE) & 0x7f )
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
    rc = vpci_add_register(pdev, vpci_cmd_read, vpci_cmd_write, PCI_COMMAND,
                           2, header);
    if ( rc )
        return rc;

    /* Disable memory decoding before sizing. */
    cmd = pci_conf_read16(seg, bus, slot, func, PCI_COMMAND);
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
            {
                pci_conf_write16(seg, bus, slot, func, PCI_COMMAND, cmd);
                return rc;
            }

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
                              &addr, &size, 0);
        if ( rc < 0 )
        {
            pci_conf_write16(seg, bus, slot, func, PCI_COMMAND, cmd);
            return rc;
        }

        if ( size == 0 )
        {
            bars[i].type = VPCI_BAR_EMPTY;
            continue;
        }

        bars[i].addr = addr;
        bars[i].size = size;
        bars[i].prefetchable = val & PCI_BASE_ADDRESS_MEM_PREFETCH;

        rc = vpci_add_register(pdev, vpci_bar_read, vpci_bar_write, reg, 4,
                               &bars[i]);
        if ( rc )
        {
            pci_conf_write16(seg, bus, slot, func, PCI_COMMAND, cmd);
            return rc;
        }
    }

    /* Check expansion ROM. */
    rc = pci_size_mem_bar(seg, bus, slot, func, rom_reg, true, &addr, &size,
                          PCI_SIZE_ROM);
    if ( rc < 0 )
    {
        pci_conf_write16(seg, bus, slot, func, PCI_COMMAND, cmd);
        return rc;
    }

    if ( size )
    {
        struct vpci_bar *rom = &header->bars[num_bars];

        rom->type = VPCI_BAR_ROM;
        rom->size = size;
        rom->addr = addr;

        rc = vpci_add_register(pdev, vpci_rom_read, vpci_rom_write, rom_reg, 4,
                               rom);
        if ( rc )
        {
            pci_conf_write16(seg, bus, slot, func, PCI_COMMAND, cmd);
            return rc;
        }
    }

    rc = 0;
    if ( cmd & PCI_COMMAND_MEMORY )
    {
        rc = vpci_modify_bars(pdev, true);
        pci_conf_write16(seg, bus, slot, func, PCI_COMMAND, cmd);
    }

    return rc;
}
REGISTER_VPCI_INIT(vpci_init_bars);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
