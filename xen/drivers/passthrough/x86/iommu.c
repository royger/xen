/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/sched.h>
#include <xen/iommu.h>
#include <xen/paging.h>
#include <xen/guest_access.h>
#include <xen/event.h>
#include <xen/softirq.h>
#include <xsm/xsm.h>

#include <asm/apicdef.h>
#include <asm/io_apic.h>
#include <asm/setup.h>

void iommu_update_ire_from_apic(
    unsigned int apic, unsigned int reg, unsigned int value)
{
    const struct iommu_ops *ops = iommu_get_ops();
    ops->update_ire_from_apic(apic, reg, value);
}

unsigned int iommu_read_apic_from_ire(unsigned int apic, unsigned int reg)
{
    const struct iommu_ops *ops = iommu_get_ops();
    return ops->read_apic_from_ire(apic, reg);
}

int __init iommu_setup_hpet_msi(struct msi_desc *msi)
{
    const struct iommu_ops *ops = iommu_get_ops();
    return ops->setup_hpet_msi ? ops->setup_hpet_msi(msi) : -ENODEV;
}

int arch_iommu_populate_page_table(struct domain *d)
{
    const struct domain_iommu *hd = dom_iommu(d);
    struct page_info *page;
    int rc = 0, n = 0;

    d->need_iommu = -1;

    this_cpu(iommu_dont_flush_iotlb) = 1;
    spin_lock(&d->page_alloc_lock);

    if ( unlikely(d->is_dying) )
        rc = -ESRCH;

    while ( !rc && (page = page_list_remove_head(&d->page_list)) )
    {
        if ( is_hvm_domain(d) ||
            (page->u.inuse.type_info & PGT_type_mask) == PGT_writable_page )
        {
            unsigned long mfn = mfn_x(page_to_mfn(page));
            unsigned long gfn = mfn_to_gmfn(d, mfn);

            if ( gfn != gfn_x(INVALID_GFN) )
            {
                ASSERT(!(gfn >> DEFAULT_DOMAIN_ADDRESS_WIDTH));
                BUG_ON(SHARED_M2P(gfn));
                rc = hd->platform_ops->map_page(d, gfn, mfn,
                                                IOMMUF_readable |
                                                IOMMUF_writable);
            }
            if ( rc )
            {
                page_list_add(page, &d->page_list);
                break;
            }
        }
        page_list_add_tail(page, &d->arch.relmem_list);
        if ( !(++n & 0xff) && !page_list_empty(&d->page_list) &&
             hypercall_preempt_check() )
            rc = -ERESTART;
    }

    if ( !rc )
    {
        /*
         * The expectation here is that generally there are many normal pages
         * on relmem_list (the ones we put there) and only few being in an
         * offline/broken state. The latter ones are always at the head of the
         * list. Hence we first move the whole list, and then move back the
         * first few entries.
         */
        page_list_move(&d->page_list, &d->arch.relmem_list);
        while ( !page_list_empty(&d->page_list) &&
                (page = page_list_first(&d->page_list),
                 (page->count_info & (PGC_state|PGC_broken))) )
        {
            page_list_del(page, &d->page_list);
            page_list_add_tail(page, &d->arch.relmem_list);
        }
    }

    spin_unlock(&d->page_alloc_lock);
    this_cpu(iommu_dont_flush_iotlb) = 0;

    if ( !rc )
        rc = iommu_iotlb_flush_all(d);

    if ( rc && rc != -ERESTART )
        iommu_teardown(d);

    return rc;
}

void __hwdom_init arch_iommu_check_autotranslated_hwdom(struct domain *d)
{
    if ( !iommu_enabled )
        panic("Presently, iommu must be enabled for PVH hardware domain\n");
}

int arch_iommu_domain_init(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    spin_lock_init(&hd->arch.mapping_lock);
    INIT_LIST_HEAD(&hd->arch.mapped_rmrrs);

    return 0;
}

void arch_iommu_domain_destroy(struct domain *d)
{
}

static bool __hwdom_init pv_inclusive_map(unsigned long pfn,
                                          unsigned long max_pfn)
{
    /*
     * If dom0-strict mode is enabled then exclude conventional RAM
     * and let the common code map dom0's pages.
     */
    if ( iommu_dom0_strict && page_is_ram_type(pfn, RAM_TYPE_CONVENTIONAL) )
        return false;
    if ( iommu_inclusive && pfn <= max_pfn )
        return !page_is_ram_type(pfn, RAM_TYPE_UNUSABLE);

    return page_is_ram_type(pfn, RAM_TYPE_CONVENTIONAL);
}

static bool __hwdom_init pvh_inclusive_map(const struct domain *d,
                                           unsigned long pfn)
{
    unsigned int i;

    /*
     * Ignore any address below 1MB, that's already identity mapped by the
     * domain builder.
     */
    if ( pfn < PFN_DOWN(MB(1)) )
        return false;

    /* Only add reserved regions. */
    if ( !page_is_ram_type(pfn, RAM_TYPE_RESERVED) )
        return false;

    /* Check that it doesn't overlap with the LAPIC */
    if ( pfn == PFN_DOWN(APIC_DEFAULT_PHYS_BASE) )
        return false;
    /* ... or the IO-APIC */
    for ( i = 0; i < nr_ioapics; i++ )
        if ( pfn == PFN_DOWN(domain_vioapic(d, i)->base_address) )
            return false;
    /* ... or the PCIe MCFG regions. */
    for ( i = 0; i < pci_mmcfg_config_num; i++ )
    {
        unsigned long addr = PFN_DOWN(pci_mmcfg_config[i].address);

        if ( pfn >= addr + (pci_mmcfg_config[i].start_bus_number << 8) &&
             pfn < addr + (pci_mmcfg_config[i].end_bus_number << 8) )
            return false;
    }

    return true;
}

void __hwdom_init arch_iommu_hwdom_init(struct domain *d)
{
    unsigned long i, j, tmp, top, max_pfn;

    if ( iommu_passthrough )
        return;

    BUG_ON(!is_hardware_domain(d));

    max_pfn = (GB(4) >> PAGE_SHIFT) - 1;
    top = max(max_pdx, pfn_to_pdx(max_pfn) + 1);

    for ( i = 0; i < top; i++ )
    {
        unsigned long pfn = pdx_to_pfn(i);
        int rc = 0;

        /*
         * Set up 1:1 mapping for dom0. Default to include only
         * conventional RAM areas and let RMRRs include needed reserved
         * regions. When set, the inclusive mapping additionally maps in
         * every pfn up to 4GB except those that fall in unusable ranges.
         */
        if ( (pfn > max_pfn && !mfn_valid(_mfn(pfn))) ||
             /* Exclude Xen bits */
             xen_in_range(pfn) )
            continue;

        if ( is_pv_domain(d) ? !pv_inclusive_map(pfn, max_pfn)
                             : !pvh_inclusive_map(d, pfn) )
            continue;

        tmp = 1 << (PAGE_SHIFT - PAGE_SHIFT_4K);
        for ( j = 0; j < tmp; j++ )
        {
            int ret;

            if ( iommu_use_hap_pt(d) )
            {
                ASSERT(is_hvm_domain(d));
                ret = set_identity_p2m_entry(d, pfn * tmp + j, p2m_access_rw,
                                             0);
            }
            else
                ret = iommu_map_page(d, pfn * tmp + j, pfn * tmp + j,
                                     IOMMUF_readable|IOMMUF_writable);

            if ( !rc )
               rc = ret;
        }

        if ( rc )
            printk(XENLOG_WARNING "d%d: IOMMU mapping failed: %d\n",
                   d->domain_id, rc);

        if (!(i & (0xfffff >> (PAGE_SHIFT - PAGE_SHIFT_4K))))
            process_pending_softirqs();
    }


}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
