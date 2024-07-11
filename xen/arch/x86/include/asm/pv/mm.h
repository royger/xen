/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * asm-x86/pv/mm.h
 *
 * Memory management interfaces for PV guests
 *
 * Copyright (C) 2017 Wei Liu <wei.liu2@citrix.com>
 */

#ifndef __X86_PV_MM_H__
#define __X86_PV_MM_H__

#ifdef CONFIG_PV

int pv_ro_page_fault(unsigned long addr, struct cpu_user_regs *regs);

int pv_set_gdt(struct vcpu *v, const unsigned long frames[],
               unsigned int entries);
void pv_destroy_gdt(struct vcpu *v);

bool pv_map_ldt_shadow_page(unsigned int off);
bool pv_destroy_ldt(struct vcpu *v);

int validate_segdesc_page(struct page_info *page);

void pv_clear_l4_guest_entries(root_pgentry_t *root_pgt);
void pv_update_shadow_l4(const struct vcpu *v, bool flush);

#else

#include <xen/errno.h>
#include <xen/lib.h>

static inline int pv_ro_page_fault(unsigned long addr,
                                   struct cpu_user_regs *regs)
{
    ASSERT_UNREACHABLE();
    return 0;
}

static inline int pv_set_gdt(struct vcpu *v, const unsigned long frames[],
                             unsigned int entries)
{ ASSERT_UNREACHABLE(); return -EINVAL; }
static inline void pv_destroy_gdt(struct vcpu *v) { ASSERT_UNREACHABLE(); }

static inline bool pv_map_ldt_shadow_page(unsigned int off) { return false; }
static inline bool pv_destroy_ldt(struct vcpu *v)
{ ASSERT_UNREACHABLE(); return false; }

static inline void pv_clear_l4_guest_entries(root_pgentry_t *root_pgt)
{ ASSERT_UNREACHABLE(); }
static inline void pv_update_shadow_l4(const struct vcpu *v, bool flush)
{ ASSERT_UNREACHABLE(); }

#endif

#endif /* __X86_PV_MM_H__ */
