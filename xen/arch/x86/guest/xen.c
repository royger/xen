/******************************************************************************
 * arch/x86/guest/xen.c
 *
 * Support for detecting and running under Xen.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#include <xen/rangeset.h>
#include <xen/types.h>
#include <xen/pv_console.h>

#include <asm/apic.h>
#include <asm/e820.h>
#include <asm/guest.h>
#include <asm/msr.h>
#include <asm/processor.h>

#include <public/arch-x86/cpuid.h>

bool xen_guest;

static uint32_t xen_cpuid_base;
extern char hypercall_page[];
static struct rangeset *mem;

DEFINE_PER_CPU(unsigned int, vcpu_id);

static struct vcpu_info *vcpu_info;
static unsigned long vcpu_info_mapped[BITS_TO_LONGS(NR_CPUS)];
DEFINE_PER_CPU(struct vcpu_info *, vcpu_info);

static void __init find_xen_leaves(void)
{
    uint32_t eax, ebx, ecx, edx, base;

    for ( base = XEN_CPUID_FIRST_LEAF;
          base < XEN_CPUID_FIRST_LEAF + 0x10000; base += 0x100 )
    {
        cpuid(base, &eax, &ebx, &ecx, &edx);

        if ( (ebx == XEN_CPUID_SIGNATURE_EBX) &&
             (ecx == XEN_CPUID_SIGNATURE_ECX) &&
             (edx == XEN_CPUID_SIGNATURE_EDX) &&
             ((eax - base) >= 2) )
        {
            xen_cpuid_base = base;
            break;
        }
    }
}

void __init probe_hypervisor(void)
{
    if ( xen_guest )
        return;

    /* Too early to use cpu_has_hypervisor */
    if ( !(cpuid_ecx(1) & cpufeat_mask(X86_FEATURE_HYPERVISOR)) )
        return;

    find_xen_leaves();

    if ( !xen_cpuid_base )
        return;

    /* Fill the hypercall page. */
    wrmsrl(cpuid_ebx(xen_cpuid_base + 2), __pa(hypercall_page));

    xen_guest = true;
}

static void map_shared_info(void)
{
    mfn_t mfn;
    struct xen_add_to_physmap xatp = {
        .domid = DOMID_SELF,
        .space = XENMAPSPACE_shared_info,
    };
    unsigned int i;
    unsigned long rc;

    if ( hypervisor_alloc_unused_page(&mfn) )
        panic("unable to reserve shared info memory page");

    xatp.gpfn = mfn_x(mfn);
    rc = xen_hypercall_memory_op(XENMEM_add_to_physmap, &xatp);
    if ( rc )
        panic("failed to map shared_info page: %ld", rc);

    set_fixmap(FIX_XEN_SHARED_INFO, mfn_x(mfn) << PAGE_SHIFT);

    /* Mask all upcalls */
    for ( i = 0; i < ARRAY_SIZE(XEN_shared_info->evtchn_mask); i++ )
        write_atomic(&XEN_shared_info->evtchn_mask[i], ~0ul);
}

static int map_vcpuinfo(void)
{
    unsigned int vcpu = this_cpu(vcpu_id);
    struct vcpu_register_vcpu_info info;
    int rc;

    if ( !vcpu_info )
    {
        this_cpu(vcpu_info) = &XEN_shared_info->vcpu_info[vcpu];
        return 0;
    }

    if ( test_bit(vcpu, vcpu_info_mapped) )
    {
        this_cpu(vcpu_info) = &vcpu_info[vcpu];
        return 0;
    }

    info.mfn = virt_to_mfn(&vcpu_info[vcpu]);
    info.offset = (unsigned long)&vcpu_info[vcpu] & ~PAGE_MASK;
    rc = xen_hypercall_vcpu_op(VCPUOP_register_vcpu_info, vcpu, &info);
    if ( rc )
    {
        BUG_ON(vcpu >= XEN_LEGACY_MAX_VCPUS);
        this_cpu(vcpu_info) = &XEN_shared_info->vcpu_info[vcpu];
    }
    else
    {
        this_cpu(vcpu_info) = &vcpu_info[vcpu];
        set_bit(vcpu, vcpu_info_mapped);
    }

    return rc;
}

static void set_vcpu_id(void)
{
    uint32_t eax, ebx, ecx, edx;

    ASSERT(xen_cpuid_base);

    /* Fetch vcpu id from cpuid. */
    cpuid(xen_cpuid_base + 4, &eax, &ebx, &ecx, &edx);
    if ( eax & XEN_HVM_CPUID_VCPU_ID_PRESENT )
        this_cpu(vcpu_id) = ebx;
    else
        this_cpu(vcpu_id) = smp_processor_id();
}

static void __init init_memmap(void)
{
    unsigned int i;

    mem = rangeset_new(NULL, "host memory map", 0);
    if ( !mem )
        panic("failed to allocate PFN usage rangeset");

    /*
     * Mark up to the last memory page (or 4GiB) as RAM. This is done because
     * Xen doesn't know the position of possible MMIO holes, so at least try to
     * avoid the know MMIO hole below 4GiB. Note that this is subject to future
     * discussion and improvements.
     */
    if ( rangeset_add_range(mem, 0, max_t(unsigned long, max_page - 1,
                                          PFN_DOWN(GB(4) - 1))) )
        panic("unable to add RAM to in-use PFN rangeset");

    for ( i = 0; i < e820.nr_map; i++ )
    {
        struct e820entry *e = &e820.map[i];

        if ( rangeset_add_range(mem, PFN_DOWN(e->addr),
                                PFN_UP(e->addr + e->size - 1)) )
            panic("unable to add range [%#lx, %#lx] to in-use PFN rangeset",
                  PFN_DOWN(e->addr), PFN_UP(e->addr + e->size - 1));
    }
}

static void xen_evtchn_upcall(struct cpu_user_regs *regs)
{
    struct vcpu_info *vcpu_info = this_cpu(vcpu_info);

    vcpu_info->evtchn_upcall_pending = 0;
    write_atomic(&vcpu_info->evtchn_pending_sel, 0);

    pv_console_rx(regs);

    ack_APIC_irq();
}

static void init_evtchn(void)
{
    static uint8_t evtchn_upcall_vector;
    int rc;

    if ( !evtchn_upcall_vector )
        alloc_direct_apic_vector(&evtchn_upcall_vector, xen_evtchn_upcall);

    ASSERT(evtchn_upcall_vector);

    rc = xen_hypercall_set_evtchn_upcall_vector(this_cpu(vcpu_id),
                                                evtchn_upcall_vector);
    if ( rc )
        panic("Unable to set evtchn upcall vector: %d", rc);
}

void __init hypervisor_setup(void)
{
    init_memmap();

    map_shared_info();

    set_vcpu_id();
    vcpu_info = xzalloc_array(struct vcpu_info, nr_cpu_ids);
    if ( map_vcpuinfo() )
    {
        xfree(vcpu_info);
        vcpu_info = NULL;
    }
    if ( !vcpu_info && nr_cpu_ids > XEN_LEGACY_MAX_VCPUS )
    {
        unsigned int i;

        for ( i = XEN_LEGACY_MAX_VCPUS; i < nr_cpu_ids; i++ )
            __cpumask_clear_cpu(i, &cpu_present_map);
        nr_cpu_ids = XEN_LEGACY_MAX_VCPUS;
        printk(XENLOG_WARNING
               "unable to map vCPU info, limiting vCPUs to: %u\n",
               XEN_LEGACY_MAX_VCPUS);
    }

    init_evtchn();
}

void hypervisor_ap_setup(void)
{
    set_vcpu_id();
    map_vcpuinfo();
    init_evtchn();
}

int hypervisor_alloc_unused_page(mfn_t *mfn)
{
    unsigned long m;
    int rc;

    rc = rangeset_claim_range(mem, 1, &m);
    if ( !rc )
        *mfn = _mfn(m);

    return rc;
}

int hypervisor_free_unused_page(mfn_t mfn)
{
    return rangeset_remove_range(mem, mfn_x(mfn), mfn_x(mfn));
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
