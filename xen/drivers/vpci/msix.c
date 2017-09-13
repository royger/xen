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

#define VMSIX_SIZE(num) offsetof(struct vpci_msix, entries[num])
#define VMSIX_ADDR_IN_RANGE(addr, table, bar)                              \
    ((addr) >= (bar)->addr + (table)->offset &&                            \
     (addr) < (bar)->addr + (table)->offset + (table)->size)

static uint32_t vpci_msix_control_read(const struct pci_dev *pdev,
                                       unsigned int reg, void *data)
{
    const struct vpci_msix *msix = data;
    uint16_t val;

    val = msix->max_entries - 1;
    val |= msix->enabled ? PCI_MSIX_FLAGS_ENABLE : 0;
    val |= msix->masked ? PCI_MSIX_FLAGS_MASKALL : 0;

    return val;
}

static void vpci_msix_control_write(const struct pci_dev *pdev,
                                    unsigned int reg, uint32_t val, void *data)
{
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    struct vpci_msix *msix = data;
    bool new_masked, new_enabled;
    unsigned int i;
    int rc;

    new_masked = val & PCI_MSIX_FLAGS_MASKALL;
    new_enabled = val & PCI_MSIX_FLAGS_ENABLE;

    /*
     * According to the PCI 3.0 specification, switching the enable bit
     * to 1 or the function mask bit to 0 should cause all the cached
     * addresses and data fields to be recalculated. Xen implements this
     * as disabling and enabling the entries.
     *
     * Note that the disable/enable sequence is only performed when the
     * guest has written to the entry (ie: updated field set) or MSIX is
     * enabled.
     */
    if ( new_enabled && !new_masked && (!msix->enabled || msix->masked) )
    {
        paddr_t table_base =
            pdev->vpci->header.bars[msix->mem[VPCI_MSIX_TABLE].bir].addr;

        for ( i = 0; i < msix->max_entries; i++ )
        {
            if ( msix->entries[i].masked ||
                 (new_enabled && msix->enabled && !msix->entries[i].updated) )
                continue;

            rc = vpci_msix_arch_disable_entry(&msix->entries[i], pdev);
            if ( rc )
            {
                gprintk(XENLOG_WARNING,
                        "%04x:%02x:%02x.%u: unable to disable entry %u: %d\n",
                        seg, bus, slot, func, msix->entries[i].nr, rc);
                return;
            }

            rc = vpci_msix_arch_enable_entry(&msix->entries[i], pdev,
                                             table_base);
            if ( rc )
            {
                gprintk(XENLOG_WARNING,
                        "%04x:%02x:%02x.%u: unable to enable entry %u: %d\n",
                        seg, bus, slot, func, msix->entries[i].nr, rc);
                /* Entry is likely not properly configured, skip it. */
                continue;
            }

            /*
             * At this point the PIRQ is still masked. Unmask it, or else the
             * guest won't receive interrupts. This is due to the
             * disable/enable sequence performed above.
             */
            vpci_msix_arch_mask_entry(&msix->entries[i], pdev, false);

            msix->entries[i].updated = false;
        }
    }
    else if ( !new_enabled && msix->enabled )
    {
        /* Guest has disabled MSIX, disable all entries. */
        for ( i = 0; i < msix->max_entries; i++ )
        {
            /*
             * NB: vpci_msix_arch_disable can be called for entries that are
             * not setup, it will return -ENOENT in that case.
             */
            rc = vpci_msix_arch_disable_entry(&msix->entries[i], pdev);
            switch ( rc )
            {
            case 0:
                /*
                 * Mark the entry successfully disabled as updated, so that on
                 * the next enable the entry is properly setup. This is done
                 * so that the following flow works correctly:
                 *
                 * mask entry -> disable MSIX -> enable MSIX -> unmask entry
                 *
                 * Without setting 'updated', the 'unmask entry' step will fail
                 * because the entry has not been updated, so it would not be
                 * mapped/bound at all.
                 */
                msix->entries[i].updated = true;
                break;
            case -ENOENT:
                /* Ignore non-present entry. */
                break;
            default:
                gprintk(XENLOG_WARNING,
                         "%04x:%02x:%02x.%u: unable to disable entry %u: %d\n",
                         seg, bus, slot, func, msix->entries[i].nr, rc);
                return;
            }
        }
    }

    if ( (new_enabled != msix->enabled || new_masked != msix->masked) &&
         pci_msi_conf_write_intercept(msix->pdev, reg, 2, &val) >= 0 )
        pci_conf_write16(seg, bus, slot, func, reg, val);

    msix->masked = new_masked;
    msix->enabled = new_enabled;
}

static struct vpci_msix *vpci_msix_find(const struct domain *d,
                                        unsigned long addr)
{
    struct vpci_msix *msix;

    list_for_each_entry ( msix, &d->arch.hvm_domain.msix_tables, next )
    {
        const struct vpci_bar *bars = msix->pdev->vpci->header.bars;
        unsigned int i;

        for ( i = 0; i < ARRAY_SIZE(msix->mem); i++ )
            if ( bars[msix->mem[i].bir].enabled &&
                 VMSIX_ADDR_IN_RANGE(addr, &msix->mem[i],
                                     &bars[msix->mem[i].bir]) )
                return msix;
    }

    return NULL;
}

static int vpci_msix_accept(struct vcpu *v, unsigned long addr)
{
    return !!vpci_msix_find(v->domain, addr);
}

static bool vpci_msix_access_allowed(const struct pci_dev *pdev,
                                     unsigned long addr, unsigned int len)
{
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);

    /* Only allow 32/64b accesses. */
    if ( len != 4 && len != 8 )
    {
        gprintk(XENLOG_WARNING,
                "%04x:%02x:%02x.%u: invalid MSI-X table access size: %u\n",
                seg, bus, slot, func, len);
        return false;
    }

    /* Only allow aligned accesses. */
    if ( (addr & (len - 1)) != 0 )
    {
        gprintk(XENLOG_WARNING,
                "%04x:%02x:%02x.%u: MSI-X only allows aligned accesses\n",
                seg, bus, slot, func);
        return false;
    }

    return true;
}

static struct vpci_msix_entry *vpci_msix_get_entry(struct vpci_msix *msix,
                                                   const struct vpci_bar *bars,
                                                   unsigned long addr)
{
    paddr_t start = bars[msix->mem[VPCI_MSIX_TABLE].bir].addr +
                    msix->mem[VPCI_MSIX_TABLE].offset;

    return &msix->entries[(addr - start) / PCI_MSIX_ENTRY_SIZE];
}

static int vpci_msix_read(struct vcpu *v, unsigned long addr,
                          unsigned int len, unsigned long *data)
{
    struct domain *d = v->domain;
    const struct vpci_bar *bars;
    struct vpci_msix *msix;
    const struct vpci_msix_entry *entry;
    unsigned int offset;

    *data = ~0ul;

    msix = vpci_msix_find(d, addr);
    if ( !msix || !vpci_msix_access_allowed(msix->pdev, addr, len) )
        return X86EMUL_OKAY;

    bars = msix->pdev->vpci->header.bars;
    if ( VMSIX_ADDR_IN_RANGE(addr, &msix->mem[VPCI_MSIX_PBA],
                             &bars[msix->mem[VPCI_MSIX_PBA].bir]) )
    {
        /*
         * Access to PBA.
         *
         * TODO: note that this relies on having the PBA identity mapped to the
         * guest address space. If this changes the address will need to be
         * translated.
         */
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

        return X86EMUL_OKAY;
    }

    spin_lock(&msix->pdev->vpci->lock);
    entry = vpci_msix_get_entry(msix, bars, addr);
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
        if ( len == 8 )
            *data |=
                (uint64_t)(entry->masked ? PCI_MSIX_VECTOR_BITMASK : 0) << 32;
        break;
    case PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET:
        *data = entry->masked ? PCI_MSIX_VECTOR_BITMASK : 0;
        break;
    default:
        ASSERT_UNREACHABLE();
        break;
    }
    spin_unlock(&msix->pdev->vpci->lock);

    return X86EMUL_OKAY;
}

static int vpci_msix_write(struct vcpu *v, unsigned long addr,
                           unsigned int len, unsigned long data)
{
    struct domain *d = v->domain;
    const struct vpci_bar *bars;
    struct vpci_msix *msix;
    struct vpci_msix_entry *entry;
    unsigned int offset;

    msix = vpci_msix_find(d, addr);
    if ( !msix || !vpci_msix_access_allowed(msix->pdev, addr, len) )
        return X86EMUL_OKAY;

    bars = msix->pdev->vpci->header.bars;
    if ( VMSIX_ADDR_IN_RANGE(addr, &msix->mem[VPCI_MSIX_PBA],
                             &bars[msix->mem[VPCI_MSIX_PBA].bir]) )
    {
        /* Ignore writes to PBA for DomUs, it's behavior is undefined. */
        if ( is_hardware_domain(d) )
        {
            switch ( len )
            {
            case 4:
                writel(data, addr);
                break;
            case 8:
                writeq(data, addr);
                break;
            default:
                ASSERT_UNREACHABLE();
                break;
            }
        }

        return X86EMUL_OKAY;
    }

    spin_lock(&msix->pdev->vpci->lock);
    entry = vpci_msix_get_entry(msix, bars, addr);
    offset = addr & (PCI_MSIX_ENTRY_SIZE - 1);

    /*
     * NB: Xen allows writes to the data/address registers with the entry
     * unmasked. The specification says this is undefined behavior, and Xen
     * implements it as storing the written value, which will be made effective
     * in the next mask/unmask cycle. This also mimics the implementation in
     * QEMU.
     */
    switch ( offset )
    {
    case PCI_MSIX_ENTRY_LOWER_ADDR_OFFSET:
        entry->updated = true;
        if ( len == 8 )
        {
            entry->addr = data;
            break;
        }
        entry->addr &= ~0xffffffff;
        entry->addr |= data;
        break;
    case PCI_MSIX_ENTRY_UPPER_ADDR_OFFSET:
        entry->updated = true;
        entry->addr &= 0xffffffff;
        entry->addr |= (uint64_t)data << 32;
        break;
    case PCI_MSIX_ENTRY_DATA_OFFSET:
        entry->updated = true;
        entry->data = data;

        if ( len == 4 )
            break;

        data >>= 32;
        /* fallthrough */
    case PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET:
    {
        bool new_masked = data & PCI_MSIX_VECTOR_BITMASK;
        const struct pci_dev *pdev = msix->pdev;
        paddr_t table_base = bars[msix->mem[VPCI_MSIX_TABLE].bir].addr;
        int rc;

        if ( entry->masked == new_masked )
            /* No change in the mask bit, nothing to do. */
            break;

        if ( !new_masked && msix->enabled && !msix->masked && entry->updated )
        {
            /*
             * If MSI-X is enabled, the function mask is not active, the entry
             * is being unmasked and there have been changes to the address or
             * data fields Xen needs to disable and enable the entry in order
             * to pick up the changes.
             */
            rc = vpci_msix_arch_disable_entry(entry, pdev);
            if ( rc && rc != -ENOENT )
            {
                gprintk(XENLOG_WARNING,
                        "%04x:%02x:%02x.%u: unable to disable entry %u: %d\n",
                        pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                        PCI_FUNC(pdev->devfn), entry->nr, rc);
                break;
            }

            rc = vpci_msix_arch_enable_entry(entry, pdev, table_base);
            if ( rc )
            {
                gprintk(XENLOG_WARNING,
                        "%04x:%02x:%02x.%u: unable to enable entry %u: %d\n",
                        pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                        PCI_FUNC(pdev->devfn), entry->nr, rc);
                break;
            }
            entry->updated = false;
        }

        vpci_msix_arch_mask_entry(entry, pdev, new_masked);
        entry->masked = new_masked;

        break;
    }
    default:
        ASSERT_UNREACHABLE();
        break;
    }
    spin_unlock(&msix->pdev->vpci->lock);

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
    struct vpci_msix_mem *table, *pba;
    unsigned int msix_offset, i, max_entries;
    uint16_t control;
    int rc;

    msix_offset = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSIX);
    if ( !msix_offset )
        return 0;

    control = pci_conf_read16(seg, bus, slot, func,
                              msix_control_reg(msix_offset));

    max_entries = msix_table_size(control);

    msix = xzalloc_bytes(VMSIX_SIZE(max_entries));
    if ( !msix )
        return -ENOMEM;

    msix->max_entries = max_entries;
    msix->pdev = pdev;

    /* Find the MSI-X table address. */
    table = &msix->mem[VPCI_MSIX_TABLE];
    table->offset = pci_conf_read32(seg, bus, slot, func,
                                    msix_table_offset_reg(msix_offset));
    table->bir = table->offset & PCI_MSIX_BIRMASK;
    table->offset &= ~PCI_MSIX_BIRMASK;
    table->size = msix->max_entries * PCI_MSIX_ENTRY_SIZE;

    /* Find the MSI-X pba address. */
    pba = &msix->mem[VPCI_MSIX_PBA];
    pba->offset = pci_conf_read32(seg, bus, slot, func,
                                  msix_pba_offset_reg(msix_offset));
    pba->bir = pba->offset & PCI_MSIX_BIRMASK;
    pba->offset &= ~PCI_MSIX_BIRMASK;
    /*
     * The spec mentions regarding to the PBA that "The last QWORD will not
     * necessarily be fully populated", so it implies that the PBA size is
     * 64-bit aligned.
     */
    pba->size = ROUNDUP(DIV_ROUND_UP(msix->max_entries, 8), 8);

    for ( i = 0; i < msix->max_entries; i++)
    {
        msix->entries[i].masked = true;
        msix->entries[i].nr = i;
        vpci_msix_arch_init_entry(&msix->entries[i]);
    }

    if ( list_empty(&d->arch.hvm_domain.msix_tables) )
        register_mmio_handler(d, &vpci_msix_table_ops);

    list_add(&msix->next, &d->arch.hvm_domain.msix_tables);

    rc = vpci_add_register(pdev, vpci_msix_control_read,
                           vpci_msix_control_write,
                           msix_control_reg(msix_offset), 2, msix);
    if ( rc )
    {
        xfree(msix);
        return rc;
    }

    pdev->vpci->msix = msix;

    return 0;
}
REGISTER_VPCI_INIT(vpci_init_msix, VPCI_PRIORITY_HIGH);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
