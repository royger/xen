/******************************************************************************
 * iocap.h
 * 
 * Architecture-specific per-domain I/O capabilities.
 */

#ifndef __X86_IOCAP_H__
#define __X86_IOCAP_H__

#include <xen/sched.h>
#include <xen/rangeset.h>

#include <asm/p2m.h>

#define ioports_access_permitted(d, s, e)               \
    rangeset_contains_range((d)->arch.ioport_caps, s, e)

#define has_arch_io_resources(d)                        \
    (!rangeset_is_empty((d)->iomem_caps) ||             \
     !rangeset_is_empty((d)->arch.ioport_caps))

static inline int ioports_permit_access(struct domain *d, unsigned long s,
                                        unsigned long e)
{
    return rangeset_add_range(d->arch.ioport_caps, s, e);
}

static inline int ioports_deny_access(struct domain *d, unsigned long s,
                                      unsigned long e)
{
    return rangeset_remove_range(d->arch.ioport_caps, s, e);
}

#endif /* __X86_IOCAP_H__ */
