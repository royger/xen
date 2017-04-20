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

static int vpci_msix_control_read(struct pci_dev *pdev, unsigned int reg,
                                  union vpci_val *val, void *data)
{
    struct vpci_msix *msix = data;

    val->word = (msix->max_entries - 1) & PCI_MSIX_FLAGS_QSIZE;
    val->word |= msix->enabled ? PCI_MSIX_FLAGS_ENABLE : 0;
    val->word |= msix->masked ? PCI_MSIX_FLAGS_MASKALL : 0;

    return 0;
}

static int vpci_msix_update_entry(struct pci_dev *pdev,
                                  struct vpci_msix_entry *entry)
{
    struct domain *d = current->domain;
    xen_domctl_bind_pt_irq_t bind = {
        .hvm_domid = DOMID_SELF,
        .irq_type = PT_IRQ_TYPE_MSI,
        .u.msi.gvec = msi_vector(entry->data),
        .u.msi.gflags = msi_flags(entry->data, entry->addr),
    };
    int rc;

    if ( entry->pirq == -1 )
    {
        unsigned int bir = pdev->vpci->msix->bir;
        struct msi_info msi_info = {
            .seg = pdev->seg,
            .bus = pdev->bus,
            .devfn = pdev->devfn,
            .table_base = pdev->vpci->header.bars[bir].paddr,
            .entry_nr = entry->nr,
        };
        int index = -1;

        /* Map PIRQ. */
        rc = allocate_and_map_msi_pirq(pdev->domain, &index, &entry->pirq,
                                       &msi_info);
        if ( rc )
        {
            gdprintk(XENLOG_ERR,
                     "%04x:%02x:%02x.%u: unable to map MSI-X PIRQ entry %u: %d\n",
                     pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                     PCI_FUNC(pdev->devfn), entry->nr, rc);
            return rc;
        }
    }

    bind.machine_irq = entry->pirq;
    pcidevs_lock();
    rc = pt_irq_create_bind(d, &bind);
    if ( rc )
    {
        gdprintk(XENLOG_ERR,
                 "%04x:%02x:%02x.%u: unable to create MSI-X bind %u: %d\n",
                 pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                 PCI_FUNC(pdev->devfn), entry->nr, rc);
        spin_lock(&pdev->domain->event_lock);
        unmap_domain_pirq(pdev->domain, entry->pirq);
        spin_unlock(&pdev->domain->event_lock);
        entry->pirq = -1;
    }
    pcidevs_unlock();

    return rc;
}

static int vpci_msix_disable_entry(struct vpci_msix_entry *entry)
{
    xen_domctl_bind_pt_irq_t bind = {
        .hvm_domid = DOMID_SELF,
        .irq_type = PT_IRQ_TYPE_MSI,
        .machine_irq = entry->pirq,
    };
    int rc;

    ASSERT(entry->pirq != -1);

    pcidevs_lock();
    rc = pt_irq_destroy_bind(current->domain, &bind);
    if ( rc )
    {
        pcidevs_unlock();
        return rc;
    }

    spin_lock(&current->domain->event_lock);
    unmap_domain_pirq(current->domain, entry->pirq);
    spin_unlock(&current->domain->event_lock);
    pcidevs_unlock();

    entry->pirq = -1;

    return 0;
}

static void vpci_msix_mask_entry(struct vpci_msix_entry *entry, bool mask)
{
    unsigned int irq;
    struct pirq *pirq;
    struct irq_desc *desc;
    unsigned long flags;

    ASSERT(entry->pirq != -1);
    pirq = pirq_info(current->domain, entry->pirq);
    ASSERT(pirq);

    irq = pirq->arch.irq;
    ASSERT(irq < nr_irqs);

    desc = irq_to_desc(irq);
    ASSERT(desc);

    spin_lock_irqsave(&desc->lock, flags);
    guest_mask_msi_irq(desc, mask);
    spin_unlock_irqrestore(&desc->lock, flags);
}

static int vpci_msix_control_write(struct pci_dev *pdev, unsigned int reg,
                                   union vpci_val val, void *data)
{
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    struct vpci_msix *msix = data;
    bool new_masked, new_enabled;
    unsigned int i;
    uint32_t data32;
    int rc;

    new_masked = val.word & PCI_MSIX_FLAGS_MASKALL;
    new_enabled = val.word & PCI_MSIX_FLAGS_ENABLE;

    if ( new_enabled != msix->enabled && new_enabled )
    {
        /* MSI-X enabled. */
        for ( i = 0; i < msix->max_entries; i++ )
        {
            if ( msix->entries[i].masked )
                continue;

            rc = vpci_msix_update_entry(pdev, &msix->entries[i]);
            if ( rc )
            {
                gdprintk(XENLOG_ERR,
                         "%04x:%02x:%02x.%u: unable to update entry %u: %d\n",
                         seg, bus, slot, func, i, rc);
                return rc;
            }

            vpci_msix_mask_entry(&msix->entries[i], false);
        }
    }
    else if ( new_enabled != msix->enabled && !new_enabled )
    {
        /* MSI-X disabled. */
        for ( i = 0; i < msix->max_entries; i++ )
        {
            if ( msix->entries[i].pirq == -1 )
                continue;

            rc = vpci_msix_disable_entry(&msix->entries[i]);
            if ( rc )
            {
                gdprintk(XENLOG_ERR,
                         "%04x:%02x:%02x.%u: unable to disable entry %u: %d\n",
                         seg, bus, slot, func, i, rc);
                return rc;
            }
        }
    }

    data32 = val.word;
    if ( (new_enabled != msix->enabled || new_masked != msix->masked) &&
         pci_msi_conf_write_intercept(pdev, reg, 2, &data32) >= 0 )
        pci_conf_write16(seg, bus, slot, func, reg, data32);

    msix->masked = new_masked;
    msix->enabled = new_enabled;

    return 0;
}

static struct vpci_msix *vpci_msix_find(struct domain *d, unsigned long addr)
{
    struct vpci_msix *msix;

    ASSERT(vpci_locked(d));
    list_for_each_entry ( msix,  &d->arch.hvm_domain.msix_tables, next )
        if ( msix->pdev->vpci->header.command & PCI_COMMAND_MEMORY &&
             addr >= msix->addr &&
             addr < msix->addr + msix->max_entries * PCI_MSIX_ENTRY_SIZE )
            return msix;

    return NULL;
}

static int vpci_msix_table_accept(struct vcpu *v, unsigned long addr)
{
    int found;

    vpci_lock(v->domain);
    found = !!vpci_msix_find(v->domain, addr);
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

    /* Do no allow accesses that span across multiple entries. */
    if ( (addr & (PCI_MSIX_ENTRY_SIZE - 1)) + len > PCI_MSIX_ENTRY_SIZE )
    {
        gdprintk(XENLOG_ERR,
                 "%04x:%02x:%02x.%u: MSI-X access crosses entry boundary\n",
                 seg, bus, slot, func);
        return -EINVAL;
    }

    /*
     * Only allow 64b accesses to the low message address field.
     *
     * NB: this is more restrictive than the specification, that allows 64b
     * accesses to other fields under certain circumstances, so this check and
     * the code will have to be fixed in order to fully comply with the
     * specification.
     */
    if ( (addr & (PCI_MSIX_ENTRY_SIZE - 1)) != 0 && len != 4 )
    {
        gdprintk(XENLOG_ERR,
                 "%04x:%02x:%02x.%u: 64bit MSI-X table access to 32bit field"
                 " (offset: %#lx len: %u)\n", seg, bus, slot, func,
                 addr & (PCI_MSIX_ENTRY_SIZE - 1), len);
        return -EINVAL;
    }

    return 0;
}

static struct vpci_msix_entry *vpci_msix_get_entry(struct vpci_msix *msix,
                                                   unsigned long addr)
{
    return &msix->entries[(addr - msix->addr) / PCI_MSIX_ENTRY_SIZE];
}

static int vpci_msix_table_read(struct vcpu *v, unsigned long addr,
                                unsigned int len, unsigned long *data)
{
    struct vpci_msix *msix;
    struct vpci_msix_entry *entry;
    unsigned int offset;

    vpci_lock(v->domain);
    msix = vpci_msix_find(v->domain, addr);
    if ( !msix )
    {
        vpci_unlock(v->domain);
        return X86EMUL_UNHANDLEABLE;
    }

    if ( vpci_msix_access_check(msix->pdev, addr, len) )
    {
        vpci_unlock(v->domain);
        return X86EMUL_UNHANDLEABLE;
    }

    /* Get the table entry and offset. */
    entry = vpci_msix_get_entry(msix, addr);
    offset = addr & (PCI_MSIX_ENTRY_SIZE - 1);

    switch ( offset )
    {
    case PCI_MSIX_ENTRY_LOWER_ADDR_OFFSET:
        *data = entry->addr;
        break;
    case PCI_MSIX_ENTRY_UPPER_ADDR_OFFSET:
        *data = entry->addr >> 32;
        break;
    case PCI_MSIX_ENTRY_DATA_OFFSET:
        *data = entry->data;
        break;
    case PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET:
        *data = entry->masked ? PCI_MSIX_VECTOR_BITMASK : 0;
        break;
    default:
        BUG();
    }
    vpci_unlock(v->domain);

    return X86EMUL_OKAY;
}

static int vpci_msix_table_write(struct vcpu *v, unsigned long addr,
                                 unsigned int len, unsigned long data)
{
    struct vpci_msix *msix;
    struct vpci_msix_entry *entry;
    unsigned int offset;

    vpci_lock(v->domain);
    msix = vpci_msix_find(v->domain, addr);
    if ( !msix )
    {
        vpci_unlock(v->domain);
        return X86EMUL_UNHANDLEABLE;
    }

    if ( vpci_msix_access_check(msix->pdev, addr, len) )
    {
        vpci_unlock(v->domain);
        return X86EMUL_UNHANDLEABLE;
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
        entry->addr &= ~GENMASK(31, 0);
        entry->addr |= data;
        break;
    case PCI_MSIX_ENTRY_UPPER_ADDR_OFFSET:
        entry->addr &= ~GENMASK(63, 32);
        entry->addr |= data << 32;
        break;
    case PCI_MSIX_ENTRY_DATA_OFFSET:
        entry->data = data;
        break;
    case PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET:
    {
        bool new_masked = data & PCI_MSIX_VECTOR_BITMASK;
        struct pci_dev *pdev = msix->pdev;
        int rc;

        if ( !msix->enabled )
        {
            ASSERT(entry->pirq == -1);
            entry->masked = new_masked;
            break;
        }

        if ( new_masked != entry->masked && !new_masked )
        {
            /* Unmasking an entry, update it. */
            rc = vpci_msix_update_entry(msix->pdev, entry);
            if ( rc )
            {
                vpci_unlock(v->domain);
                gdprintk(XENLOG_ERR,
                         "%04x:%02x:%02x.%u: unable to update entry %u: %d\n",
                         pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                         PCI_FUNC(pdev->devfn), entry->nr, rc);
                return X86EMUL_UNHANDLEABLE;
            }
        }

        vpci_msix_mask_entry(entry, new_masked);
        entry->masked = new_masked;

        break;
    }
    default:
        BUG();
    }
    vpci_unlock(v->domain);

    return X86EMUL_OKAY;
}

static const struct hvm_mmio_ops vpci_msix_table_ops = {
    .check = vpci_msix_table_accept,
    .read = vpci_msix_table_read,
    .write = vpci_msix_table_write,
};

static int vpci_init_msix(struct pci_dev *pdev)
{
    struct domain *d = pdev->domain;
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    struct vpci_msix *msix;
    unsigned int msix_offset, i, max_entries;
    paddr_t msix_paddr;
    uint16_t control;
    int rc;

    msix_offset = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSIX);
    if ( !msix_offset )
        return 0;

    if ( !dom0_msix )
    {
        xen_vpci_mask_capability(pdev, PCI_CAP_ID_MSIX);
        return 0;
    }

    control = pci_conf_read16(seg, bus, slot, func,
                              msix_control_reg(msix_offset));

    /* Get the maximum number of vectors the device supports. */
    max_entries = msix_table_size(control);
    if ( !max_entries )
        return 0;

    msix = xzalloc_bytes(MSIX_SIZE(max_entries));
    if ( !msix )
        return -ENOMEM;

    msix->max_entries = max_entries;
    msix->pdev = pdev;

    /* Find the MSI-X table address. */
    msix->offset = pci_conf_read32(seg, bus, slot, func,
                                   msix_table_offset_reg(msix_offset));
    msix->bir = msix->offset & PCI_MSIX_BIRMASK;
    msix->offset &= ~PCI_MSIX_BIRMASK;

    ASSERT(pdev->vpci->header.bars[msix->bir].type == VPCI_BAR_MEM ||
           pdev->vpci->header.bars[msix->bir].type == VPCI_BAR_MEM64_LO);
    msix->addr = pdev->vpci->header.bars[msix->bir].mapped_addr + msix->offset;
    msix_paddr = pdev->vpci->header.bars[msix->bir].paddr + msix->offset;

    for ( i = 0; i < msix->max_entries; i++)
    {
        msix->entries[i].masked = true;
        msix->entries[i].nr = i;
        msix->entries[i].pirq = -1;
    }

    if ( list_empty(&d->arch.hvm_domain.msix_tables) )
        register_mmio_handler(d, &vpci_msix_table_ops);

    list_add(&msix->next, &d->arch.hvm_domain.msix_tables);

    rc = xen_vpci_add_register(pdev, vpci_msix_control_read,
                               vpci_msix_control_write,
                               msix_control_reg(msix_offset), 2, msix);
    if ( rc )
    {
        dprintk(XENLOG_ERR,
                "%04x:%02x:%02x.%u: failed to add handler for MSI-X control: %d\n",
                seg, bus, slot, func, rc);
        goto error;
    }

    if ( pdev->vpci->header.command & PCI_COMMAND_MEMORY )
    {
        /* Unmap this memory from the guest. */
        rc = modify_mmio(pdev->domain, PFN_DOWN(msix->addr),
                         PFN_DOWN(msix_paddr),
                         PFN_UP(msix->max_entries * PCI_MSIX_ENTRY_SIZE),
                         false);
        if ( rc )
        {
            dprintk(XENLOG_ERR,
                    "%04x:%02x:%02x.%u: unable to unmap MSI-X BAR region: %d\n",
                    seg, bus, slot, func, rc);
            goto error;
        }
    }

    pdev->vpci->msix = msix;

    return 0;

 error:
    ASSERT(rc);
    xfree(msix);
    return rc;
}

REGISTER_VPCI_INIT(vpci_init_msix, false);

static void vpci_dump_msix(unsigned char key)
{
    struct domain *d;
    struct pci_dev *pdev;

    printk("Guest MSI-X information:\n");

    for_each_domain ( d )
    {
        if ( !has_vpci(d) )
            continue;

        vpci_lock(d);
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

            printk("Guest entries:\n");
            for ( i = 0; i < msix->max_entries; i++ )
            {
                struct vpci_msix_entry *entry = &msix->entries[i];
                uint32_t data = entry->data;
                uint64_t addr = entry->addr;

                printk("%4u vec=%#02x%7s%6s%3sassert%5s%7s dest_id=%lu mask=%u pirq=%d\n",
                       i,
                       (data & MSI_DATA_VECTOR_MASK) >> MSI_DATA_VECTOR_SHIFT,
                       data & MSI_DATA_DELIVERY_LOWPRI ? "lowest" : "fixed",
                       data & MSI_DATA_TRIGGER_LEVEL ? "level" : "edge",
                       data & MSI_DATA_LEVEL_ASSERT ? "" : "de",
                       addr & MSI_ADDR_DESTMODE_LOGIC ? "log" : "phys",
                       addr & MSI_ADDR_REDIRECTION_LOWPRI ? "lowest" : "cpu",
                       (addr & MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT,
                       entry->masked, entry->pirq);
            }
            printk("\n");
        }
        vpci_unlock(d);
    }
}

static int __init vpci_msix_setup_keyhandler(void)
{
    register_keyhandler('X', vpci_dump_msix, "dump guest MSI-X state", 1);
    return 0;
}
__initcall(vpci_msix_setup_keyhandler);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

