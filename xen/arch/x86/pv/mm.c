/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * pv/mm.c
 *
 * Memory managment code for PV guests
 *
 * Copyright (c) 2002-2005 K A Fraser
 * Copyright (c) 2004 Christian Limpach
 */

#include <xen/guest_access.h>

#include <asm/current.h>
#include <asm/fixmap.h>
#include <asm/p2m.h>
#include <asm/pv/domain.h>

#include "mm.h"

/*
 * Get a mapping of a PV guest's l1e for this linear address.  The return
 * pointer should be unmapped using unmap_domain_page().
 */
l1_pgentry_t *map_guest_l1e(unsigned long linear, mfn_t *gl1mfn)
{
    l2_pgentry_t l2e;

    ASSERT(!paging_mode_translate(current->domain));
    ASSERT(!paging_mode_external(current->domain));

    if ( unlikely(!__addr_ok(linear)) )
        return NULL;

    /* Find this l1e and its enclosing l1mfn in the linear map. */
    if ( get_unsafe(l2e, &__linear_l2_table[l2_linear_offset(linear)]) )
        return NULL;

    /* Check flags that it will be safe to read the l1e. */
    if ( (l2e_get_flags(l2e) & (_PAGE_PRESENT | _PAGE_PSE)) != _PAGE_PRESENT )
        return NULL;

    *gl1mfn = l2e_get_mfn(l2e);

    return (l1_pgentry_t *)map_domain_page(*gl1mfn) + l1_table_offset(linear);
}

/*
 * Map a guest's LDT page (covering the byte at @offset from start of the LDT)
 * into Xen's virtual range.  Returns true if the mapping changed, false
 * otherwise.
 */
bool pv_map_ldt_shadow_page(unsigned int offset)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    struct page_info *page;
    l1_pgentry_t gl1e, *pl1e;
    unsigned long linear = curr->arch.pv.ldt_base + offset;

    BUG_ON(unlikely(in_irq()));

    /*
     * Prior limit checking should guarantee this property.  NB. This is
     * safe as updates to the LDT can only be made by MMUEXT_SET_LDT to the
     * current vcpu, and vcpu_reset() will block until this vcpu has been
     * descheduled before continuing.
     */
    if ( unlikely((offset >> 3) >= curr->arch.pv.ldt_ents) )
    {
        ASSERT_UNREACHABLE();
        return false;
    }

    if ( is_pv_32bit_domain(currd) )
        linear = (uint32_t)linear;

    gl1e = guest_get_eff_kern_l1e(linear);
    if ( unlikely(!(l1e_get_flags(gl1e) & _PAGE_PRESENT)) )
        return false;

    page = get_page_from_gfn(currd, l1e_get_pfn(gl1e), NULL, P2M_ALLOC);
    if ( unlikely(!page) )
        return false;

    if ( unlikely(!get_page_type(page, PGT_seg_desc_page)) )
    {
        put_page(page);
        return false;
    }

    pl1e = &pv_ldt_ptes(curr)[offset >> PAGE_SHIFT];
    l1e_add_flags(gl1e, _PAGE_RW);

    l1e_write(pl1e, gl1e);

    return true;
}

#ifdef CONFIG_PV32
void init_xen_pae_l2_slots(l2_pgentry_t *l2t, const struct domain *d)
{
    memcpy(&l2t[COMPAT_L2_PAGETABLE_FIRST_XEN_SLOT(d)],
           compat_idle_pg_table_l2,
           COMPAT_L2_PAGETABLE_XEN_SLOTS(d) * sizeof(*l2t));
}
#endif

static void asi_copy_l4(root_pgentry_t *dst, const root_pgentry_t *src,
                        bool is_64bit)
{
    if ( is_64bit )
    {
        unsigned int i;

        for ( i = 0; i < ROOT_PAGETABLE_FIRST_XEN_SLOT; i++ )
            l4e_write(&dst[i], src[i]);
        for ( i = ROOT_PAGETABLE_LAST_XEN_SLOT + 1;
              i < L4_PAGETABLE_ENTRIES; i++ )
            l4e_write(&dst[i], src[i]);

        l4e_write(&dst[l4_table_offset(RO_MPT_VIRT_START)],
                  src[l4_table_offset(RO_MPT_VIRT_START)]);
    }
    else
        l4e_write(&dst[0], src[0]);
}

void pv_asi_update_shadow_l4(const struct vcpu *v, bool new_cr3)
{
    const root_pgentry_t *guest_pgt = percpu_fix_to_virt(PCPU_PV_L4_GUEST);
    root_pgentry_t *root_pgt = percpu_fix_to_virt(PCPU_PV_L4_SHADOW);
    const struct domain *d = v->domain;

    ASSERT(!d->arch.pv.xpti);
    ASSERT(is_pv_domain(d));
    ASSERT(!is_idle_domain(d));

    if ( new_cr3 )
    {
        percpu_set_fixmap(PCPU_PV_L4_GUEST, maddr_to_mfn(cr3_pa(v->arch.cr3)),
                          __PAGE_HYPERVISOR_RO);

#ifdef CONFIG_SHADOW_PAGING
        if ( paging_mode_enabled(d) )
        {
            l4e_write(&root_pgt[l4_table_offset(LINEAR_PT_VIRT_START)],
                      guest_pgt[l4_table_offset(LINEAR_PT_VIRT_START)]);
            l4e_write(&root_pgt[l4_table_offset(SH_LINEAR_PT_VIRT_START)],
                      guest_pgt[l4_table_offset(SH_LINEAR_PT_VIRT_START)]);
        }
#endif
    }

    asi_copy_l4(root_pgt, guest_pgt, is_pv_64bit_domain(d));
}

void pv_asi_vcpu_deschedule(const struct vcpu *v)
{
    /*
     * De-scheduling a PV vCPU with ASI enabled.
     *
     * Don't leak the L4 shadow mapping in the per-CPU area.  Can't be done
     * in paravirt_ctxt_switch_from() because the lazy idle vCPU context
     * switch would otherwise enter an infinite loop in
     * mapcache_current_vcpu() with sync_local_execstate().
     *
     * Note clearing the fixmap must strictly be done ahead of changing the
     * current vCPU and with interrupts disabled, so there's no window
     * where current->domain->arch.asi == true and PCPU_FIX_PV_L4SHADOW is
     * not mapped.
     */
    percpu_clear_fixmap(PCPU_PV_L4_SHADOW);
    percpu_clear_fixmap(PCPU_PV_L4_GUEST);
}

void pv_asi_vcpu_schedule(const struct vcpu *v)
{
    const struct domain *d = v->domain;
    const root_pgentry_t *guest_pgt =
        map_domain_page(maddr_to_mfn(cr3_pa(v->arch.cr3)));
    root_pgentry_t *root_pgt =
        map_domain_page(page_to_mfn(v->arch.pv.root_pgt));

    setup_perdomain_slot(d, root_pgt);
    asi_copy_l4(root_pgt, guest_pgt, is_pv_64bit_domain(d));

#ifdef CONFIG_SHADOW_PAGING
    if ( paging_mode_enabled(d) )
    {
        l4e_write(&root_pgt[l4_table_offset(LINEAR_PT_VIRT_START)],
                  guest_pgt[l4_table_offset(LINEAR_PT_VIRT_START)]);
        l4e_write(&root_pgt[l4_table_offset(SH_LINEAR_PT_VIRT_START)],
                  guest_pgt[l4_table_offset(SH_LINEAR_PT_VIRT_START)]);
    }
#endif

    unmap_domain_page(guest_pgt);
    unmap_domain_page(root_pgt);

    /*
     * Setup the pCPU fixmap entries, they however might not be reachable at
     * this point by not running on a page-table with the per-CPU slot setup.
     */
    percpu_set_fixmap(PCPU_PV_L4_GUEST, maddr_to_mfn(cr3_pa(v->arch.cr3)),
                      __PAGE_HYPERVISOR_RO);
    percpu_set_fixmap(PCPU_PV_L4_SHADOW, page_to_mfn(v->arch.pv.root_pgt),
                      __PAGE_HYPERVISOR_RW);
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
