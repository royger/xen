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

#include <xen/p2m-common.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/vpci.h>

#include <asm/event.h>

#define MAPPABLE_BAR(x)                                                 \
    ((x)->type == VPCI_BAR_MEM32 || (x)->type == VPCI_BAR_MEM64_LO ||   \
     (x)->type == VPCI_BAR_ROM)

struct map_data {
    struct domain *d;
    bool map;
};

static int map_range(unsigned long s, unsigned long e, void *data,
                     unsigned long *c)
{
    const struct map_data *map = data;
    int rc;

    for ( ; ; )
    {
        unsigned long size = e - s + 1;

        /*
         * ARM TODOs:
         * - On ARM whether the memory is prefetchable or not should be passed
         *   to map_mmio_regions in order to decide which memory attributes
         *   should be used.
         *
         * - {un}map_mmio_regions doesn't support preemption, hence the bodge
         *   below in order to limit the amount of mappings to 64 pages for
         *   each function call.
         */

#ifdef CONFIG_ARM
        size = min(64ul, size);
#endif

        rc = (map->map ? map_mmio_regions : unmap_mmio_regions)
             (map->d, _gfn(s), size, _mfn(s));
        if ( rc == 0 )
        {
            *c += size;
#ifdef CONFIG_ARM
            rc = -ERESTART;
#endif
            break;
        }
        if ( rc < 0 )
        {
            printk(XENLOG_G_WARNING
                   "Failed to identity %smap [%" PRI_gfn ", %" PRI_gfn ") for d%d: %d\n",
                   map ? "" : "un", s, e, map->d->domain_id, rc);
            break;
        }
        ASSERT(rc < size);
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

static void modify_decoding(const struct pci_dev *pdev, bool map, bool rom)
{
    struct vpci_header *header = &pdev->vpci->header;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        if ( rom && header->bars[i].type == VPCI_BAR_ROM )
        {
            unsigned int rom_pos = (i == 6) ? PCI_ROM_ADDRESS
                                            : PCI_ROM_ADDRESS1;
            uint32_t val = pci_conf_read32(pdev->seg, pdev->bus, slot, func,
                                           rom_pos);

            header->bars[i].enabled = header->rom_enabled = map;

            val &= ~PCI_ROM_ADDRESS_ENABLE;
            val |= map ? PCI_ROM_ADDRESS_ENABLE : 0;
            pci_conf_write32(pdev->seg, pdev->bus, slot, func, rom_pos, val);
            break;
        }
        if ( !rom && (header->bars[i].type != VPCI_BAR_ROM ||
                      header->rom_enabled) )
            header->bars[i].enabled = map;
    }

    if ( !rom )
    {
        uint16_t cmd = pci_conf_read16(pdev->seg, pdev->bus, slot,
                                       func, PCI_COMMAND);

        cmd &= ~PCI_COMMAND_MEMORY;
        cmd |= map ? PCI_COMMAND_MEMORY : 0;
        pci_conf_write16(pdev->seg, pdev->bus, slot, func, PCI_COMMAND,
                         cmd);
    }
}

bool vpci_process_pending(struct vcpu *v)
{
    while ( v->vpci.mem )
    {
        struct map_data data = {
            .d = v->domain,
            .map = v->vpci.map,
        };

        switch ( rangeset_consume_ranges(v->vpci.mem, map_range, &data) )
        {
        case -ERESTART:
            return true;

        default:
            if ( v->vpci.map )
            {
                spin_lock(&v->vpci.pdev->vpci->lock);
                modify_decoding(v->vpci.pdev, v->vpci.map, v->vpci.rom);
                spin_unlock(&v->vpci.pdev->vpci->lock);
            }
            /* fallthrough. */
        case -ENOMEM:
            /*
             * Other errors are ignored, hoping that at least some regions
             * will be mapped and that would be enough for the device to
             * function. Note that in the unmap case the memory decoding or
             * ROM enable bit have already been toggled off before attempting
             * to perform the p2m unmap.
             */
            rangeset_destroy(v->vpci.mem);
            v->vpci.mem = NULL;
            break;
        }
    }

    return false;
}

static void maybe_defer_map(struct domain *d, const struct pci_dev *pdev,
                            struct rangeset *mem, bool map, bool rom)
{
    struct vcpu *curr = current;

    if ( is_idle_vcpu(curr) )
    {
        struct map_data data = { .d = d, .map = true };

        /*
         * Only used for domain construction in order to map the BARs
         * of devices with memory decoding enabled.
         */
        ASSERT(map && !rom);
        rangeset_consume_ranges(mem, map_range, &data);
        modify_decoding(pdev, true, false);
        rangeset_destroy(mem);
    }
    else
    {
        /*
         * NB: when deferring the {un}map the state of the device should not be
         * trusted. For example the enable bit is toggled after the device is
         * mapped. This can lead to parallel mapping operations being started
         * for the same device if the domain is not well-behaved.
         *
         * In any case, the worse that can happen are errors from the {un}map
         * operations, which will lead to the devices not working properly.
         */
        ASSERT(curr->domain == d);
        curr->vpci.pdev = pdev;
        curr->vpci.mem = mem;
        curr->vpci.map = map;
        curr->vpci.rom = rom;
    }
}

static void modify_bars(const struct pci_dev *pdev, bool map, bool rom)
{
    struct vpci_header *header = &pdev->vpci->header;
    struct rangeset *mem = rangeset_new(NULL, NULL, 0);
    const struct pci_dev *tmp;
    unsigned int i;
    int rc;

    if ( !map )
        modify_decoding(pdev, false, rom);

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

    /*
     * First fill the rangeset with all the BARs of this device or with the ROM
     * BAR only, depending on whether the guest is toggling the memory decode
     * bit of the command register, or the enable bit of the ROM BAR register.
     */
    for ( i = 0; i < ARRAY_SIZE(header->bars); i++ )
    {
        const struct vpci_bar *bar = &header->bars[i];

        if ( !MAPPABLE_BAR(bar) ||
             (rom ? bar->type != VPCI_BAR_ROM
                  : (bar->type == VPCI_BAR_ROM && !header->rom_enabled)) )
            continue;

        rc = rangeset_add_range(mem, PFN_DOWN(bar->addr),
                                PFN_UP(bar->addr + bar->size - 1));
        if ( rc )
        {
            printk(XENLOG_G_WARNING
                   "Failed to add [%" PRI_gfn ", %" PRI_gfn "): %d\n",
                   PFN_DOWN(bar->addr), PFN_UP(bar->addr + bar->size - 1),
                   rc);
            rangeset_destroy(mem);
            return;
        }
    }

    /*
     * Check for overlaps with other BARs. Note that only BARs that are
     * currently mapped (enabled) are checked for overlaps.
     */
    list_for_each_entry(tmp, &pdev->domain->arch.pdev_list, domain_list)
        for ( i = 0; i < ARRAY_SIZE(tmp->vpci->header.bars); i++ )
        {
            const struct vpci_bar *bar = &tmp->vpci->header.bars[i];
            unsigned long start = PFN_DOWN(bar->addr);
            unsigned long end = PFN_UP(bar->addr + bar->size - 1);

            if ( !bar->enabled || !rangeset_overlaps_range(mem, start, end) )
                continue;

            rc = rangeset_remove_range(mem, start, end);
            if ( rc )
            {
                printk(XENLOG_G_WARNING
                       "Failed to remove [%" PRI_gfn ", %" PRI_gfn "): %d\n",
                       start, end, rc);
                rangeset_destroy(mem);
                return;
            }
        }

    maybe_defer_map(pdev->domain, pdev, mem, map, rom);
}

static void cmd_write(const struct pci_dev *pdev, unsigned int reg,
                      uint32_t cmd, void *data)
{
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    uint16_t current_cmd = pci_conf_read16(pdev->seg, pdev->bus, slot, func,
                                           reg);

    /*
     * Let Dom0 play with all the bits directly except for the memory
     * decoding one.
     */
    if ( (cmd ^ current_cmd) & PCI_COMMAND_MEMORY )
        modify_bars(pdev, cmd & PCI_COMMAND_MEMORY, false);
    else
        pci_conf_write16(pdev->seg, pdev->bus, slot, func, reg, cmd);
}

static void bar_write(const struct pci_dev *pdev, unsigned int reg,
                      uint32_t val, void *data)
{
    struct vpci_bar *bar = data;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    bool hi = false;

    if ( pci_conf_read16(pdev->seg, pdev->bus, slot, func, PCI_COMMAND) &
         PCI_COMMAND_MEMORY )
    {
        gprintk(XENLOG_WARNING,
                "%04x:%02x:%02x.%u: ignored BAR %lu write with memory decoding enabled\n",
                pdev->seg, pdev->bus, slot, func,
                bar - pdev->vpci->header.bars);
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

static void rom_write(const struct pci_dev *pdev, unsigned int reg,
                      uint32_t val, void *data)
{
    struct vpci_header *header = &pdev->vpci->header;
    struct vpci_bar *rom = data;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    uint16_t cmd = pci_conf_read16(pdev->seg, pdev->bus, slot, func,
                                   PCI_COMMAND);
    bool new_enabled = val & PCI_ROM_ADDRESS_ENABLE;

    if ( (cmd & PCI_COMMAND_MEMORY) && header->rom_enabled && new_enabled )
    {
        gprintk(XENLOG_WARNING,
                "%04x:%02x:%02x.%u: ignored ROM BAR write with memory decoding enabled\n",
                pdev->seg, pdev->bus, slot, func);
        return;
    }

    if ( !header->rom_enabled )
        rom->addr = val & PCI_ROM_ADDRESS_MASK;

    /* Check if ROM BAR should be mapped/unmapped. */
    if ( (cmd & PCI_COMMAND_MEMORY) && header->rom_enabled != new_enabled )
        modify_bars(pdev, new_enabled, true);
    else
    {
        header->rom_enabled = new_enabled;
        pci_conf_write32(pdev->seg, pdev->bus, slot, func, reg, val);
    }

    if ( !new_enabled )
        rom->addr = val & PCI_ROM_ADDRESS_MASK;
}

static int init_bars(struct pci_dev *pdev)
{
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    uint16_t cmd;
    uint64_t addr, size;
    unsigned int i, num_bars, rom_reg;
    struct vpci_header *header = &pdev->vpci->header;
    struct vpci_bar *bars = header->bars;
    pci_sbdf_t sbdf = {
        .seg = pdev->seg,
        .bus = pdev->bus,
        .dev = slot,
        .func = func,
    };
    int rc;

    switch ( pci_conf_read8(pdev->seg, pdev->bus, slot, func, PCI_HEADER_TYPE)
             & 0x7f )
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
    rc = vpci_add_register(pdev->vpci, vpci_hw_read16, cmd_write, PCI_COMMAND,
                           2, header);
    if ( rc )
        return rc;

    /* Disable memory decoding before sizing. */
    cmd = pci_conf_read16(pdev->seg, pdev->bus, slot, func, PCI_COMMAND);
    if ( cmd & PCI_COMMAND_MEMORY )
        pci_conf_write16(pdev->seg, pdev->bus, slot, func, PCI_COMMAND,
                         cmd & ~PCI_COMMAND_MEMORY);

    for ( i = 0; i < num_bars; i++ )
    {
        uint8_t reg = PCI_BASE_ADDRESS_0 + i * 4;
        uint32_t val;

        if ( i && bars[i - 1].type == VPCI_BAR_MEM64_LO )
        {
            bars[i].type = VPCI_BAR_MEM64_HI;
            rc = vpci_add_register(pdev->vpci, vpci_hw_read32, bar_write, reg,
                                   4, &bars[i]);
            if ( rc )
            {
                pci_conf_write16(pdev->seg, pdev->bus, slot, func,
                                 PCI_COMMAND, cmd);
                return rc;
            }

            continue;
        }

        val = pci_conf_read32(pdev->seg, pdev->bus, slot, func, reg);
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

        rc = pci_size_mem_bar(sbdf, reg, &addr, &size,
                              (i == num_bars - 1) ? PCI_BAR_LAST : 0);
        if ( rc < 0 )
        {
            pci_conf_write16(pdev->seg, pdev->bus, slot, func, PCI_COMMAND,
                             cmd);
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

        rc = vpci_add_register(pdev->vpci, vpci_hw_read32, bar_write, reg, 4,
                               &bars[i]);
        if ( rc )
        {
            pci_conf_write16(pdev->seg, pdev->bus, slot, func, PCI_COMMAND,
                             cmd);
            return rc;
        }
    }

    /* Check expansion ROM. */
    rc = pci_size_mem_bar(sbdf, rom_reg, &addr, &size, PCI_BAR_ROM);
    if ( rc > 0 && size )
    {
        struct vpci_bar *rom = &header->bars[num_bars];

        rom->type = VPCI_BAR_ROM;
        rom->size = size;
        rom->addr = addr;
        header->rom_enabled = pci_conf_read32(pdev->seg, pdev->bus, slot, func,
                                              rom_reg) & PCI_ROM_ADDRESS_ENABLE;

        rc = vpci_add_register(pdev->vpci, vpci_hw_read32, rom_write, rom_reg,
                               4, rom);
        if ( rc )
            rom->type = VPCI_BAR_EMPTY;
    }

    if ( cmd & PCI_COMMAND_MEMORY )
        modify_bars(pdev, true, false);

    return 0;
}
REGISTER_VPCI_INIT(init_bars, VPCI_PRIORITY_MIDDLE);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
