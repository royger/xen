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

void pv_clear_l4_guest_entries(root_pgentry_t *root_pgt)
{
    memset(root_pgt, 0,
           sizeof(root_pgentry_t) * ROOT_PAGETABLE_FIRST_XEN_SLOT);
    memset(root_pgt + ROOT_PAGETABLE_LAST_XEN_SLOT + 1, 0,
           sizeof(root_pgentry_t) *
           (L4_PAGETABLE_ENTRIES - ROOT_PAGETABLE_LAST_XEN_SLOT - 1));
}

void pv_update_shadow_l4(const struct vcpu *v, bool flush)
{
    const root_pgentry_t *guest_pgt = percpu_fix_to_virt(PCPU_FIX_PV_L4SHADOW);
    root_pgentry_t *shadow_pgt = this_cpu(root_pgt);

    ASSERT(!v->domain->arch.pv.xpti);
    ASSERT(!is_idle_vcpu(v));

    if ( get_cpu_info()->new_cr3 )
    {
        percpu_set_fixmap(PCPU_FIX_PV_L4SHADOW, maddr_to_mfn(v->arch.cr3),
                          __PAGE_HYPERVISOR_RO);
        get_cpu_info()->new_cr3 = false;
    }

    if ( is_pv_32bit_vcpu(v) )
        shadow_pgt[0] = guest_pgt[0];
    else
    {
        unsigned int i;

        for ( i = 0; i < ROOT_PAGETABLE_FIRST_XEN_SLOT; i++ )
            shadow_pgt[i] = guest_pgt[i];
        for ( i = ROOT_PAGETABLE_LAST_XEN_SLOT + 1;
              i < L4_PAGETABLE_ENTRIES; i++ )
            shadow_pgt[i] = guest_pgt[i];

        /* The presence of this Xen slot is selected by the guest. */
        shadow_pgt[l4_table_offset(RO_MPT_VIRT_START)] =
            guest_pgt[l4_table_offset(RO_MPT_VIRT_START)];
    }

    if ( flush )
        flush_local(FLUSH_TLB_GLOBAL);
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
