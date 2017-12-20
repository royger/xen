/******************************************************************************
 * arch/x86/pv/shim.c
 *
 * Functionaltiy for PV Shim mode
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
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/init.h>
#include <xen/shutdown.h>
#include <xen/types.h>

#include <asm/apic.h>
#include <asm/dom0_build.h>
#include <asm/guest.h>
#include <asm/pv/mm.h>

#include <public/arch-x86/cpuid.h>

#ifndef CONFIG_PV_SHIM_EXCLUSIVE
bool pv_shim;
boolean_param("pv-shim", pv_shim);
#endif

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_USER| \
                 _PAGE_GUEST_KERNEL)
#define COMPAT_L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)

static void __init replace_va_mapping(struct domain *d, l4_pgentry_t *l4start,
                                      unsigned long va, unsigned long mfn)
{
    struct page_info *page;
    l4_pgentry_t *pl4e;
    l3_pgentry_t *pl3e;
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;

    pl4e = l4start + l4_table_offset(va);
    pl3e = l4e_to_l3e(*pl4e);
    pl3e += l3_table_offset(va);
    pl2e = l3e_to_l2e(*pl3e);
    pl2e += l2_table_offset(va);
    pl1e = l2e_to_l1e(*pl2e);
    pl1e += l1_table_offset(va);

    page = mfn_to_page(l1e_get_pfn(*pl1e));
    put_page_and_type(page);

    *pl1e = l1e_from_pfn(mfn, (!is_pv_32bit_domain(d) ? L1_PROT
                                                      : COMPAT_L1_PROT));
}

static void evtchn_reserve(const struct domain *d, unsigned int port)
{
    ASSERT(port_is_valid(d, port));
    evtchn_from_port(d, port)->state = ECS_RESERVED;
    BUG_ON(xen_hypercall_evtchn_unmask(port));
}

static bool evtchn_handled(const struct domain *d, unsigned int port)
{
    ASSERT(port_is_valid(d, port));
    /* The shim manages VIRQs, the rest is forwarded to L0. */
    return evtchn_from_port(d, port)->state == ECS_VIRQ;
}

static void evtchn_assign_vcpu(const struct domain *d, unsigned int port,
                               unsigned int vcpu)
{
    ASSERT(port_is_valid(d, port));
    evtchn_from_port(d, port)->notify_vcpu_id = vcpu;
}

void __init pv_shim_setup_dom(struct domain *d, l4_pgentry_t *l4start,
                              unsigned long va_start, unsigned long store_va,
                              unsigned long console_va, unsigned long vphysmap,
                              start_info_t *si)
{
    uint64_t param = 0;
    long rc;

#define SET_AND_MAP_PARAM(p, si, va) ({                                        \
    rc = xen_hypercall_hvm_get_param(p, &param);                               \
    if ( rc )                                                                  \
        panic("Unable to get " #p "\n");                                       \
    (si) = param;                                                              \
    if ( va )                                                                  \
    {                                                                          \
        BUG_ON(unshare_xen_page_with_guest(mfn_to_page(param), dom_io));       \
        share_xen_page_with_guest(mfn_to_page(param), d, XENSHARE_writable);   \
        replace_va_mapping(d, l4start, va, param);                             \
        dom0_update_physmap(d, PFN_DOWN((va) - va_start), param, vphysmap);    \
    }                                                                          \
    else                                                                       \
    {                                                                          \
        BUG_ON(evtchn_allocate_port(d, param));                                \
        evtchn_reserve(d, param);                                              \
    }                                                                          \
})
    SET_AND_MAP_PARAM(HVM_PARAM_STORE_PFN, si->store_mfn, store_va);
    SET_AND_MAP_PARAM(HVM_PARAM_STORE_EVTCHN, si->store_evtchn, 0);
    if ( !pv_console )
    {
        SET_AND_MAP_PARAM(HVM_PARAM_CONSOLE_PFN, si->console.domU.mfn,
                          console_va);
        SET_AND_MAP_PARAM(HVM_PARAM_CONSOLE_EVTCHN, si->console.domU.evtchn, 0);
    }
#undef SET_AND_MAP_PARAM
}

void pv_shim_shutdown(uint8_t reason)
{
    /* XXX: handle suspend */
    xen_hypercall_shutdown(reason);
}

long pv_shim_event_channel_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct domain *d = current->domain;
    struct evtchn_close close;
    long rc;

    switch ( cmd )
    {
#define EVTCHN_FORWARD(cmd, port_field)                                     \
    case EVTCHNOP_##cmd: {                                                  \
        struct evtchn_##cmd op;                                             \
                                                                            \
        if ( copy_from_guest(&op, arg, 1) != 0 )                            \
            return -EFAULT;                                                 \
                                                                            \
        rc = xen_hypercall_event_channel_op(EVTCHNOP_##cmd, &op);           \
        if ( rc )                                                           \
            break;                                                          \
                                                                            \
        spin_lock(&d->event_lock);                                          \
        rc = evtchn_allocate_port(d, op.port_field);                        \
        if ( rc )                                                           \
        {                                                                   \
            close.port = op.port_field;                                     \
            BUG_ON(xen_hypercall_event_channel_op(EVTCHNOP_close, &close)); \
        }                                                                   \
        else                                                                \
            evtchn_reserve(d, op.port_field);                               \
        spin_unlock(&d->event_lock);                                        \
                                                                            \
        if ( !rc && __copy_to_guest(arg, &op, 1) )                          \
            rc = -EFAULT;                                                   \
                                                                            \
        break;                                                              \
        }

    EVTCHN_FORWARD(alloc_unbound, port)
    EVTCHN_FORWARD(bind_interdomain, local_port)
#undef EVTCHN_FORWARD

    case EVTCHNOP_bind_virq: {
        struct evtchn_bind_virq virq;
        struct evtchn_alloc_unbound alloc = {
            .dom = DOMID_SELF,
            .remote_dom = DOMID_SELF,
        };

        if ( copy_from_guest(&virq, arg, 1) != 0 )
            return -EFAULT;
        /*
         * The event channel space is actually controlled by L0 Xen, so
         * allocate a port from L0 and then force the VIRQ to be bound to that
         * specific port.
         *
         * This is only required for VIRQ because the rest of the event channel
         * operations are handled directly by L0.
         */
        rc = xen_hypercall_event_channel_op(EVTCHNOP_alloc_unbound, &alloc);
        if ( rc )
           break;

        /* Force L1 to use the event channel port allocated on L0. */
        rc = evtchn_bind_virq(&virq, alloc.port);
        if ( rc )
        {
            close.port = alloc.port;
            BUG_ON(xen_hypercall_event_channel_op(EVTCHNOP_close, &close));
        }

        if ( !rc && __copy_to_guest(arg, &virq, 1) )
            rc = -EFAULT;

        break;
    }

    case EVTCHNOP_status: {
        struct evtchn_status status;

        if ( copy_from_guest(&status, arg, 1) != 0 )
            return -EFAULT;

        /*
         * NB: if the event channel is not handled by the shim, just forward
         * the status request to L0, even if the port is not valid.
         */
        if ( port_is_valid(d, status.port) && evtchn_handled(d, status.port) )
            rc = evtchn_status(&status);
        else
            rc = xen_hypercall_event_channel_op(EVTCHNOP_status, &status);

        break;
    }

    case EVTCHNOP_bind_vcpu: {
        struct evtchn_bind_vcpu vcpu;

        if ( copy_from_guest(&vcpu, arg, 1) != 0 )
            return -EFAULT;

        if ( !port_is_valid(d, vcpu.port) )
            return -EINVAL;

        if ( evtchn_handled(d, vcpu.port) )
            rc = evtchn_bind_vcpu(vcpu.port, vcpu.vcpu);
        else
        {
            rc = xen_hypercall_event_channel_op(EVTCHNOP_bind_vcpu, &vcpu);
            if ( !rc )
                 evtchn_assign_vcpu(d, vcpu.port, vcpu.vcpu);
        }

        break;
    }

    case EVTCHNOP_close: {
        if ( copy_from_guest(&close, arg, 1) != 0 )
            return -EFAULT;

        if ( !port_is_valid(d, close.port) )
            return -EINVAL;

        set_bit(close.port, XEN_shared_info->evtchn_mask);

        if ( evtchn_handled(d, close.port) )
        {
            rc = evtchn_close(d, close.port, true);
            if ( rc )
                break;
        }
        else
            evtchn_free(d, evtchn_from_port(d, close.port));

        rc = xen_hypercall_event_channel_op(EVTCHNOP_close, &close);
        if ( rc )
            /*
             * If the port cannot be closed on the L0 mark it as reserved
             * in the shim to avoid re-using it.
             */
            evtchn_reserve(d, close.port);

        break;
    }

    case EVTCHNOP_bind_ipi: {
        struct evtchn_bind_ipi ipi;

        if ( copy_from_guest(&ipi, arg, 1) != 0 )
            return -EFAULT;

        rc = xen_hypercall_event_channel_op(EVTCHNOP_bind_ipi, &ipi);
        if ( rc )
            break;

        spin_lock(&d->event_lock);
        rc = evtchn_allocate_port(d, ipi.port);
        if ( rc )
        {
            spin_unlock(&d->event_lock);

            close.port = ipi.port;
            BUG_ON(xen_hypercall_event_channel_op(EVTCHNOP_close, &close));
            break;
        }

        evtchn_assign_vcpu(d, ipi.port, ipi.vcpu);
        evtchn_reserve(d, ipi.port);
        spin_unlock(&d->event_lock);

        if ( __copy_to_guest(arg, &ipi, 1) )
            rc = -EFAULT;

        break;
    }

    case EVTCHNOP_unmask: {
        struct evtchn_unmask unmask;

        if ( copy_from_guest(&unmask, arg, 1) != 0 )
            return -EFAULT;

        /* Unmask is handled in L1 */
        rc = evtchn_unmask(unmask.port);

        break;
    }

    case EVTCHNOP_send: {
        struct evtchn_send send;

        if ( copy_from_guest(&send, arg, 1) != 0 )
            return -EFAULT;

        rc = xen_hypercall_event_channel_op(EVTCHNOP_send, &send);

        break;
    }

    case EVTCHNOP_reset: {
        struct evtchn_reset reset;

        if ( copy_from_guest(&reset, arg, 1) != 0 )
            return -EFAULT;

        rc = xen_hypercall_event_channel_op(EVTCHNOP_reset, &reset);

        break;
    }

    default:
        /* No FIFO or PIRQ support for now */
        rc = -EOPNOTSUPP;
        break;
    }

    return rc;
}

void pv_shim_inject_evtchn(unsigned int port)
{
    if ( port_is_valid(pv_domain, port) )
    {
         struct evtchn *chn = evtchn_from_port(pv_domain, port);

         evtchn_port_set_pending(pv_domain, chn->notify_vcpu_id, chn);
    }
}

domid_t get_initial_domain_id(void)
{
    uint32_t eax, ebx, ecx, edx;

    if ( !pv_shim )
        return 0;

    cpuid(hypervisor_cpuid_base() + 4, &eax, &ebx, &ecx, &edx);

    return (eax & XEN_HVM_CPUID_DOMID_PRESENT) ? ecx : 1;
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
