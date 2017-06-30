/*
 * Handlers for accesses to the MSI-X capability structure and the memory
 * region.
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
#include <asm/msi.h>
#include <xen/p2m-common.h>
#include <xen/keyhandler.h>

#define MSIX_SIZE(num) (offsetof(struct vpci_msix, entries[num]))
#define MSIX_ADDR_IN_RANGE(a, table)                                    \
    ((table)->addr != INVALID_PADDR && (a) >= (table)->addr &&          \
     (a) < (table)->addr + (table)->size)

static void vpci_msix_control_read(struct pci_dev *pdev, unsigned int reg,
                                   union vpci_val *val, void *data)
{
    const struct vpci_msix *msix = data;

    val->u16 = (msix->max_entries - 1) & PCI_MSIX_FLAGS_QSIZE;
    val->u16 |= msix->enabled ? PCI_MSIX_FLAGS_ENABLE : 0;
    val->u16 |= msix->masked ? PCI_MSIX_FLAGS_MASKALL : 0;
}

static void vpci_msix_control_write(struct pci_dev *pdev, unsigned int reg,
                                    union vpci_val val, void *data)
{
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    struct vpci_msix *msix = data;
    paddr_t table_base = pdev->vpci->header.bars[msix->table.bir].addr;
    bool new_masked, new_enabled;
    unsigned int i;
    int rc;

    new_masked = val.u16 & PCI_MSIX_FLAGS_MASKALL;
    new_enabled = val.u16 & PCI_MSIX_FLAGS_ENABLE;

    if ( !msix->enabled && new_enabled )
    {
        /* MSI-X enabled. */
        for ( i = 0; i < msix->max_entries; i++ )
        {
            if ( msix->entries[i].masked )
                continue;

            rc = vpci_msix_arch_enable(&msix->entries[i].arch, pdev,
                                       msix->entries[i].addr,
                                       msix->entries[i].data,
                                       msix->entries[i].nr, table_base);
            if ( rc )
            {
                gdprintk(XENLOG_ERR,
                         "%04x:%02x:%02x.%u: unable to update entry %u: %d\n",
                         seg, bus, slot, func, i, rc);
                return;
            }

            vpci_msix_arch_mask(&msix->entries[i].arch, pdev, false);
        }
    }
    else if ( msix->enabled && !new_enabled )
    {
        /* MSI-X disabled. */
        for ( i = 0; i < msix->max_entries; i++ )
        {
            rc = vpci_msix_arch_disable(&msix->entries[i].arch, pdev);
            if ( rc )
            {
                gdprintk(XENLOG_ERR,
                         "%04x:%02x:%02x.%u: unable to disable entry %u: %d\n",
                         seg, bus, slot, func, i, rc);
                return;
            }
        }
    }

    if ( (new_enabled != msix->enabled || new_masked != msix->masked) &&
         pci_msi_conf_write_intercept(pdev, reg, 2, &val.u32) >= 0 )
        pci_conf_write16(seg, bus, slot, func, reg, val.u32);

    msix->masked = new_masked;
    msix->enabled = new_enabled;
}

static struct vpci_msix *vpci_msix_find(struct domain *d, unsigned long addr)
{
    struct vpci_msix *msix;

    ASSERT(vpci_locked(d));
    list_for_each_entry ( msix,  &d->arch.hvm_domain.msix_tables, next )
    {
        uint8_t seg = msix->pdev->seg, bus = msix->pdev->bus;
        uint8_t slot = PCI_SLOT(msix->pdev->devfn);
        uint8_t func = PCI_FUNC(msix->pdev->devfn);
        uint16_t cmd = pci_conf_read16(seg, bus, slot, func, PCI_COMMAND);

        if ( (cmd & PCI_COMMAND_MEMORY) &&
             (MSIX_ADDR_IN_RANGE(addr, &msix->table) ||
             MSIX_ADDR_IN_RANGE(addr, &msix->pba)) )
            return msix;
    }

    return NULL;
}

static int vpci_msix_accept(struct vcpu *v, unsigned long addr)
{
    bool found;

    vpci_lock(v->domain);
    found = vpci_msix_find(v->domain, addr);
    vpci_unlock(v->domain);

    return found;
}

static int vpci_msix_access_check(struct pci_dev *pdev, unsigned long addr,
                                  unsigned int len)
{
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);

    /* Only allow 32/64b accesses. */
    if ( len != 4 && len != 8 )
    {
        gdprintk(XENLOG_ERR,
                 "%04x:%02x:%02x.%u: invalid MSI-X table access size: %u\n",
                 seg, bus, slot, func, len);
        return -EINVAL;
    }

    /* Only allow aligned accesses. */
    if ( (addr & (len - 1)) != 0 )
    {
        gdprintk(XENLOG_ERR,
                 "%04x:%02x:%02x.%u: MSI-X only allows aligned accesses\n",
                 seg, bus, slot, func);
        return -EINVAL;
    }

    return 0;
}

static struct vpci_msix_entry *vpci_msix_get_entry(struct vpci_msix *msix,
                                                   unsigned long addr)
{
    return &msix->entries[(addr - msix->table.addr) / PCI_MSIX_ENTRY_SIZE];
}

static int vpci_msix_read(struct vcpu *v, unsigned long addr,
                          unsigned int len, unsigned long *data)
{
    struct domain *d = v->domain;
    struct vpci_msix *msix;
    const struct vpci_msix_entry *entry;
    unsigned int offset;

    vpci_lock(d);

    msix = vpci_msix_find(d, addr);
    if ( !msix )
    {
        vpci_unlock(d);
        *data = ~0ul;
        return X86EMUL_OKAY;
    }

    if ( vpci_msix_access_check(msix->pdev, addr, len) )
    {
        vpci_unlock(d);
        *data = ~0ul;
        return X86EMUL_OKAY;
    }

    if ( MSIX_ADDR_IN_RANGE(addr, &msix->pba) )
    {
        /* Access to PBA. */
        switch ( len )
        {
        case 4:
            *data = readl(addr);
            break;
        case 8:
            *data = readq(addr);
            break;
        default:
            ASSERT_UNREACHABLE();
            break;
        }

        vpci_unlock(d);
        return X86EMUL_OKAY;
    }

    /* Get the table entry and offset. */
    entry = vpci_msix_get_entry(msix, addr);
    offset = addr & (PCI_MSIX_ENTRY_SIZE - 1);

    switch ( offset )
    {
    case PCI_MSIX_ENTRY_LOWER_ADDR_OFFSET:
        /*
         * NB: do explicit truncation to the size of the access. This shouldn't
         * be required here, since the caller of the handler should already
         * take the appropriate measures to truncate the value before returning
         * to the guest, but better be safe than sorry.
         */
        *data = len == 8 ? entry->addr : (uint32_t)entry->addr;
        break;
    case PCI_MSIX_ENTRY_UPPER_ADDR_OFFSET:
        *data = entry->addr >> 32;
        break;
    case PCI_MSIX_ENTRY_DATA_OFFSET:
        *data = entry->data;
        if ( len == 8 )
            *data |=
                (uint64_t)(entry->masked ? PCI_MSIX_VECTOR_BITMASK : 0) << 32;
        break;
    case PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET:
        *data = entry->masked ? PCI_MSIX_VECTOR_BITMASK : 0;
        break;
    default:
        BUG();
    }
    vpci_unlock(d);

    return X86EMUL_OKAY;
}

static int vpci_msix_write(struct vcpu *v, unsigned long addr,
                                 unsigned int len, unsigned long data)
{
    struct domain *d = v->domain;
    struct vpci_msix *msix;
    struct vpci_msix_entry *entry;
    unsigned int offset;

    vpci_lock(d);
    msix = vpci_msix_find(d, addr);
    if ( !msix )
    {
        vpci_unlock(d);
        return X86EMUL_OKAY;
    }

    if ( MSIX_ADDR_IN_RANGE(addr, &msix->pba) )
    {
        /* Ignore writes to PBA, it's behavior is undefined. */
        vpci_unlock(d);
        return X86EMUL_OKAY;
    }

    if ( vpci_msix_access_check(msix->pdev, addr, len) )
    {
        vpci_unlock(d);
        return X86EMUL_OKAY;
    }

    /* Get the table entry and offset. */
    entry = vpci_msix_get_entry(msix, addr);
    offset = addr & (PCI_MSIX_ENTRY_SIZE - 1);

    switch ( offset )
    {
    case PCI_MSIX_ENTRY_LOWER_ADDR_OFFSET:
        if ( len == 8 )
        {
            entry->addr = data;
            break;
        }
        entry->addr &= ~0xffffffff;
        entry->addr |= data;
        break;
    case PCI_MSIX_ENTRY_UPPER_ADDR_OFFSET:
        entry->addr &= ~((uint64_t)0xffffffff << 32);
        entry->addr |= data << 32;
        break;
    case PCI_MSIX_ENTRY_DATA_OFFSET:
        /*
         * 8 byte writes to the msg data and vector control fields are
         * only allowed if the entry is masked.
         */
        if ( len == 8 && !entry->masked && !msix->masked && msix->enabled )
        {
            vpci_unlock(d);
            return X86EMUL_OKAY;
        }

        entry->data = data;

        if ( len == 4 )
            break;

        data >>= 32;
        /* fallthrough */
    case PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET:
    {
        bool new_masked = data & PCI_MSIX_VECTOR_BITMASK;
        struct pci_dev *pdev = msix->pdev;
        paddr_t table_base = pdev->vpci->header.bars[msix->table.bir].addr;
        int rc;

        if ( !msix->enabled )
        {
            entry->masked = new_masked;
            break;
        }

        if ( new_masked != entry->masked && !new_masked )
        {
            /* Unmasking an entry, update it. */
            rc = vpci_msix_arch_enable(&entry->arch, pdev, entry->addr,
                                       entry->data, entry->nr, table_base);
            if ( rc )
            {
                vpci_unlock(d);
                gdprintk(XENLOG_ERR,
                         "%04x:%02x:%02x.%u: unable to update entry %u: %d\n",
                         pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                         PCI_FUNC(pdev->devfn), entry->nr, rc);
                return X86EMUL_OKAY;
            }
        }

        vpci_msix_arch_mask(&entry->arch, pdev, new_masked);
        entry->masked = new_masked;

        break;
    }
    default:
        BUG();
    }
    vpci_unlock(d);

    return X86EMUL_OKAY;
}

static const struct hvm_mmio_ops vpci_msix_table_ops = {
    .check = vpci_msix_accept,
    .read = vpci_msix_read,
    .write = vpci_msix_write,
};

static int vpci_init_msix(struct pci_dev *pdev)
{
    struct domain *d = pdev->domain;
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    struct vpci_msix *msix;
    unsigned int msix_offset, i, max_entries;
    struct vpci_bar *table_bar, *pba_bar;
    uint16_t control;
    int rc;

    msix_offset = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSIX);
    if ( !msix_offset )
        return 0;

    control = pci_conf_read16(seg, bus, slot, func,
                              msix_control_reg(msix_offset));

    /* Get the maximum number of vectors the device supports. */
    max_entries = msix_table_size(control);

    msix = xzalloc_bytes(MSIX_SIZE(max_entries));
    if ( !msix )
        return -ENOMEM;

    msix->max_entries = max_entries;
    msix->pdev = pdev;

    /* Find the MSI-X table address. */
    msix->table.offset = pci_conf_read32(seg, bus, slot, func,
                                         msix_table_offset_reg(msix_offset));
    msix->table.bir = msix->table.offset & PCI_MSIX_BIRMASK;
    msix->table.offset &= ~PCI_MSIX_BIRMASK;
    msix->table.size = msix->max_entries * PCI_MSIX_ENTRY_SIZE;
    msix->table.addr = INVALID_PADDR;

    /* Find the MSI-X pba address. */
    msix->pba.offset = pci_conf_read32(seg, bus, slot, func,
                                       msix_pba_offset_reg(msix_offset));
    msix->pba.bir = msix->pba.offset & PCI_MSIX_BIRMASK;
    msix->pba.offset &= ~PCI_MSIX_BIRMASK;
    msix->pba.size = DIV_ROUND_UP(msix->max_entries, 8);
    msix->pba.addr = INVALID_PADDR;

    for ( i = 0; i < msix->max_entries; i++)
    {
        msix->entries[i].masked = true;
        msix->entries[i].nr = i;
        vpci_msix_arch_init(&msix->entries[i].arch);
    }

    if ( list_empty(&d->arch.hvm_domain.msix_tables) )
        register_mmio_handler(d, &vpci_msix_table_ops);

    list_add(&msix->next, &d->arch.hvm_domain.msix_tables);

    rc = vpci_add_register(pdev, vpci_msix_control_read,
                           vpci_msix_control_write,
                           msix_control_reg(msix_offset), 2, msix);
    if ( rc )
    {
        dprintk(XENLOG_ERR,
                "%04x:%02x:%02x.%u: failed to add handler for MSI-X control: %d\n",
                seg, bus, slot, func, rc);
        goto error;
    }

    table_bar = &pdev->vpci->header.bars[msix->table.bir];
    pba_bar = &pdev->vpci->header.bars[msix->pba.bir];

    /*
     * The header handlers will take care of leaving a hole for the MSI-X
     * related areas, that's why MSI-X needs to be initialized before the
     * header.
     */
    table_bar->msix[VPCI_BAR_MSIX_TABLE] = &msix->table;
    pba_bar->msix[VPCI_BAR_MSIX_PBA] = &msix->pba;
    pdev->vpci->msix = msix;

    return 0;

 error:
    ASSERT(rc);
    xfree(msix);
    return rc;
}

REGISTER_VPCI_INIT(vpci_init_msix, VPCI_PRIORITY_HIGH);

void vpci_dump_msix(void)
{
    struct domain *d;
    struct pci_dev *pdev;

    for_each_domain ( d )
    {
        if ( !has_vpci(d) )
            continue;

        printk("vPCI MSI-X information for guest %u\n", d->domain_id);

        if ( !vpci_trylock(d) )
        {
            printk("Unable to get vPCI lock, skipping\n");
            continue;
        }

        list_for_each_entry ( pdev, &d->arch.pdev_list, domain_list)
        {
            uint8_t seg = pdev->seg, bus = pdev->bus;
            uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
            struct vpci_msix *msix = pdev->vpci->msix;
            unsigned int i;

            if ( !msix )
                continue;

            printk("Device %04x:%02x:%02x.%u\n", seg, bus, slot, func);

            printk("Max entries: %u maskall: %u enabled: %u\n",
                   msix->max_entries, msix->masked, msix->enabled);

            printk("Guest table entries:\n");
            for ( i = 0; i < msix->max_entries; i++ )
                vpci_msix_arch_print(&msix->entries[i].arch,
                                     msix->entries[i].data,
                                     msix->entries[i].addr,
                                     msix->entries[i].masked, i);
        }
        vpci_unlock(d);
    }
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

