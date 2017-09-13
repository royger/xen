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
#include <xen/softirq.h>

#include <asm/event.h>

#define MAPPABLE_BAR(x)                                                 \
    ((x)->type == VPCI_BAR_MEM32 || (x)->type == VPCI_BAR_MEM64_LO ||   \
     (x)->type == VPCI_BAR_ROM)

struct map_data {
    struct domain *d;
    bool map;
};

static int vpci_map_range(unsigned long s, unsigned long e, void *data,
                          unsigned long *c)
{
    const struct map_data *map = data;
    int rc;

    for ( ; ; )
    {
        unsigned long size = e - s + 1;

        rc = (map->map ? map_mmio_regions : unmap_mmio_regions)
             (map->d, _gfn(s), size, _mfn(s));
        if ( rc == 0 )
        {
            *c += size;
            break;
        }
        if ( rc < 0 )
        {
            printk(XENLOG_WARNING
                   "Failed to identity %smap [%" PRI_gfn ", %" PRI_gfn ") for d%d: %d\n",
                   map ? "" : "un", s, e, map->d->domain_id, rc);
            break;
        }
        *c += rc;
        s += rc;
        if ( general_preempt_check() )
        {
            if ( !is_idle_vcpu(current) )
                return -ERESTART;

            process_pending_softirqs();
        }
    }

    return rc;
}

static int vpci_map_memory(struct domain *d, struct rangeset *mem, bool map)
{
    struct map_data data = { .d = d, .map = map };

    return rangeset_consume_ranges(mem, vpci_map_range, &data);
}

bool vpci_check_pending(struct vcpu *v)
{
    if ( v->vpci.mem )
    {
        int rc = vpci_map_memory(v->domain, v->vpci.mem, v->vpci.map);

        if ( rc == -ERESTART )
            return true;

        rangeset_destroy(v->vpci.mem);
        v->vpci.mem = NULL;
    }

    return false;
}

static int vpci_maybe_defer_map(struct domain *d, struct rangeset *mem,
                                bool map)
{
    struct vcpu *curr = current;
    int rc = 0;

    if ( is_idle_vcpu(curr) )
    {
        rc = vpci_map_memory(d, mem, map);
        rangeset_destroy(mem);
    }
    else
    {
        ASSERT(curr->domain == d);
        curr->vpci.mem = mem;
        curr->vpci.map = map;
    }

    return rc;
}

static int vpci_check_bar_overlap(const struct pci_dev *pdev,
                                  const struct vpci_bar *rom,
                                  struct rangeset *mem)
{
    const struct pci_dev *cmp;

    /* Check for overlaps with other device's BARs. */
    list_for_each_entry(cmp, &pdev->domain->arch.pdev_list, domain_list)
    {
        unsigned int i;

        if ( rom == NULL && pdev == cmp )
            continue;

        for ( i = 0; i < ARRAY_SIZE(cmp->vpci->header.bars); i++ )
        {
            const struct vpci_bar *bar = &cmp->vpci->header.bars[i];
            unsigned long start = PFN_DOWN(bar->addr);
            unsigned long end = PFN_DOWN(bar->addr + bar->size - 1);
            int rc;

            if ( rom == bar || !bar->enabled || !MAPPABLE_BAR(bar) ||
                 !rangeset_overlaps_range(mem, start, end) )
                continue;

            rc = rangeset_remove_range(mem, start, end);
            if ( rc )
                return rc;
        }
    }

    return 0;
}

static void vpci_modify_bars(const struct pci_dev *pdev, bool map)
{
    struct vpci_header *header = &pdev->vpci->header;
    struct vpci_msix *msix = pdev->vpci->msix;
    struct rangeset *mem = rangeset_new(NULL, NULL, 0);
    unsigned int i;
    int rc;

    if ( !mem )
        return;

    /*
     * Create a rangeset that represents the current device BARs memory region
     * and compare it against all the currently active BAR memory regions. If
     * an overlap is found, subtract it from the region to be
     * mapped/unmapped.
     *
     * NB: the rangeset uses inclusive frame numbers.
     */

    /* First fill the rangeset with all the BARs of this device. */
    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        const struct vpci_bar *bar = &header->bars[i];

        if ( !MAPPABLE_BAR(bar) ||
             (bar->type == VPCI_BAR_ROM && !bar->rom_enabled) )
            continue;

        rc = rangeset_add_range(mem, PFN_DOWN(bar->addr),
                                PFN_DOWN(bar->addr + bar->size - 1));
        if ( rc )
        {
            rangeset_destroy(mem);
            return;
        }
    }

    /* Remove any MSIX regions if present. */
    for ( i = 0; msix && i < ARRAY_SIZE(msix->mem); i++ )
    {
        paddr_t start =
            header->bars[msix->mem[i].bir].addr + msix->mem[i].offset;

        rc = rangeset_remove_range(mem, PFN_DOWN(start),
                                   PFN_DOWN(start + msix->mem[i].size - 1));
        if ( rc )
        {
            rangeset_destroy(mem);
            return;
        }
    }

    /* Check for overlaps with other device's BARs. */
    rc = vpci_check_bar_overlap(pdev, NULL, mem);
    if ( rc )
    {
        rangeset_destroy(mem);
        return;
    }

    rc = vpci_maybe_defer_map(pdev->domain, mem, map);
    if ( !rc )
        for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
            if ( header->bars[i].type != VPCI_BAR_ROM ||
                 header->bars[i].rom_enabled )
            header->bars[i].enabled = map;
}

static void vpci_modify_rom(const struct pci_dev *pdev,
                            struct vpci_bar *rom, bool map)
{
    struct rangeset *mem = rangeset_new(NULL, NULL, 0);
    int rc;

    ASSERT(rom->type == VPCI_BAR_ROM);

    if ( !mem )
        return;

    /* First fill the rangeset with the ROM BAR. */
    rc = rangeset_add_range(mem, PFN_DOWN(rom->addr),
                            PFN_DOWN(rom->addr + rom->size - 1));
    if ( rc )
    {
        rangeset_destroy(mem);
        return;
    }

    /*
     * Check for overlaps with other BARs (either on this device or other
     * devices).
     */
    rc = vpci_check_bar_overlap(pdev, rom, mem);
    if ( rc )
    {
        rangeset_destroy(mem);
        return;
    }

    rc = vpci_maybe_defer_map(pdev->domain, mem, map);
    if ( !rc )
        rom->enabled = map;
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
        vpci_modify_bars(pdev, cmd & PCI_COMMAND_MEMORY);

    pci_conf_write16(seg, bus, slot, func, reg, cmd);
}

static uint32_t vpci_bar_read(const struct pci_dev *pdev, unsigned int reg,
                              void *data)
{
    return pci_conf_read32(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                           PCI_FUNC(pdev->devfn), reg);
}

static void vpci_bar_write(const struct pci_dev *pdev, unsigned int reg,
                           uint32_t val, void *data)
{
    struct vpci_bar *bar = data;
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    bool hi = false;

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
    }
    else
        val &= PCI_BASE_ADDRESS_MEM_MASK;

    /*
     * Update the cached address, so that when memory decoding is enabled
     * Xen can map the BAR into the guest p2m.
     */
    bar->addr &= ~(0xffffffffull << (hi ? 32 : 0));
    bar->addr |= (uint64_t)val << (hi ? 32 : 0);

    /* Make sure Xen writes back the same value for the BAR RO bits. */
    if ( !hi )
    {
        val |= bar->type == VPCI_BAR_MEM32 ? PCI_BASE_ADDRESS_MEM_TYPE_32
                                           : PCI_BASE_ADDRESS_MEM_TYPE_64;
        val |= bar->prefetchable ? PCI_BASE_ADDRESS_MEM_PREFETCH : 0;
    }

    pci_conf_write32(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                     PCI_FUNC(pdev->devfn), reg, val);
}

static void vpci_rom_write(const struct pci_dev *pdev, unsigned int reg,
                           uint32_t val, void *data)
{
    struct vpci_bar *rom = data;
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    uint16_t cmd = pci_conf_read16(seg, bus, slot, func, PCI_COMMAND);

    if ( (pci_conf_read16(seg, bus, slot, func, PCI_COMMAND) &
          PCI_COMMAND_MEMORY) && rom->rom_enabled )
    {
         gprintk(XENLOG_WARNING,
                 "%04x:%02x:%02x.%u: ignored ROM BAR write with memory decoding enabled\n",
                 seg, bus, slot, func);
        return;
    }

    rom->addr = val & PCI_ROM_ADDRESS_MASK;

    /* Check if ROM BAR should be mapped/unmapped. */
    if ( (cmd & PCI_COMMAND_MEMORY) &&
         rom->rom_enabled != (val & PCI_ROM_ADDRESS_ENABLE) )
        vpci_modify_rom(pdev, rom, val & PCI_ROM_ADDRESS_ENABLE);

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
    pci_sbdf_t sbdf = {
        .seg = seg,
        .bus = bus,
        .dev = slot,
        .func = func,
    };
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
        rc = pci_size_mem_bar(sbdf, reg, i == num_bars - 1, &addr, &size, 0);
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
    rc = pci_size_mem_bar(sbdf, rom_reg, true, &addr, &size, PCI_BAR_ROM);
    if ( rc > 0 && size )
    {
        struct vpci_bar *rom = &header->bars[num_bars];

        rom->type = VPCI_BAR_ROM;
        rom->size = size;
        rom->addr = addr;

        rc = vpci_add_register(pdev, vpci_bar_read, vpci_rom_write, rom_reg, 4,
                               rom);
        if ( rc )
            rom->type = VPCI_BAR_EMPTY;
    }

    if ( cmd & PCI_COMMAND_MEMORY )
    {
        vpci_modify_bars(pdev, true);
        pci_conf_write16(seg, bus, slot, func, PCI_COMMAND, cmd);
    }

    return 0;
}
REGISTER_VPCI_INIT(vpci_init_bars, VPCI_PRIORITY_MIDDLE);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
