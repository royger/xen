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

void pv_maybe_update_shadow_l4(struct vcpu *v)
{
    if ( !is_pv_vcpu(v) || is_idle_vcpu(v) || !v->domain->arch.asi )
        return;

    ASSERT(!v->domain->arch.pv.xpti);
    ASSERT(mfn_eq(maddr_to_mfn(v->arch.cr3),
                  _mfn(virt_to_mfn(this_cpu(root_pgt)))));

    copy_page(this_cpu(root_pgt), (void *)PERCPU_VIRT_START);

    setup_perdomain_slot(v, this_cpu(root_pgt));
}

mfn_t pv_maybe_shadow_l4(struct vcpu *v, mfn_t mfn)
{
    if ( !is_pv_vcpu(v) || is_idle_vcpu(v) || !v->domain->arch.asi )
        return mfn;

    ASSERT(!v->domain->arch.pv.xpti);

    v->arch.pv.guest_l4 = mfn;

    if ( this_cpu(root_pgt) )
        map_pages_to_xen(PERCPU_VIRT_START, v->arch.pv.guest_l4, 1,
                         __PAGE_HYPERVISOR_RO);

    /*
     * No need to copy the contents of the guest L4 to the per-CPU shadow.
     * This will be done in write_ptbase() by calling
     * pv_maybe_update_shadow_l4() ahead of the actual CR3 write.
     *
     * When creating a PV dom0 the build code will call make_cr3() and switch
     * to the dom0 page-tables before the per-CPU root_pgt is allocated for the
     * BSP.  Map the guest L4 in preparation for doing the copy later when the
     * vCPU is started.  Note that the vCPU cr3 is adjusted to use the per-CPU
     * root_pgt as part of the context switch logic in
     * paravirt_ctxt_switch_to().
     *
     * pv_maybe_update_shadow_l4() doesn't need a similar adjustment because
     * the PV dom0 building code explicitly avoid calling write_ptbase(), and
     * instead uses switch_cr3_cr4().
     */

    ASSERT(this_cpu(root_pgt) || system_state < SYS_STATE_active);

    return this_cpu(root_pgt) ? _mfn(virt_to_mfn(this_cpu(root_pgt))) : mfn;
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
