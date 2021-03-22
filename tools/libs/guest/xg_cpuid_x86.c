/******************************************************************************
 * xc_cpuid_x86.c
 *
 * Compute cpuid of a domain.
 *
 * Copyright (c) 2008, Citrix Systems, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include "xg_private.h"
#include <xen/hvm/params.h>
#include <xen-tools/libs.h>

enum {
#define XEN_CPUFEATURE(name, value) X86_FEATURE_##name = value,
#include <xen/arch-x86/cpufeatureset.h>
};

#include <xen/asm/x86-vendors.h>

#define bitmaskof(idx)      (1u << ((idx) & 31))
#define featureword_of(idx) ((idx) >> 5)

int xc_get_cpu_levelling_caps(xc_interface *xch, uint32_t *caps)
{
    DECLARE_SYSCTL;
    int ret;

    sysctl.cmd = XEN_SYSCTL_get_cpu_levelling_caps;
    ret = do_sysctl(xch, &sysctl);

    if ( !ret )
        *caps = sysctl.u.cpu_levelling_caps.caps;

    return ret;
}

int xc_get_cpu_featureset(xc_interface *xch, uint32_t index,
                          uint32_t *nr_features, uint32_t *featureset)
{
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(featureset,
                             *nr_features * sizeof(*featureset),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int ret;

    if ( xc_hypercall_bounce_pre(xch, featureset) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_get_cpu_featureset;
    sysctl.u.cpu_featureset.index = index;
    sysctl.u.cpu_featureset.nr_features = *nr_features;
    set_xen_guest_handle(sysctl.u.cpu_featureset.features, featureset);

    ret = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, featureset);

    if ( !ret )
        *nr_features = sysctl.u.cpu_featureset.nr_features;

    return ret;
}

uint32_t xc_get_cpu_featureset_size(void)
{
    return FEATURESET_NR_ENTRIES;
}

const uint32_t *xc_get_static_cpu_featuremask(
    enum xc_static_cpu_featuremask mask)
{
    static const uint32_t masks[][FEATURESET_NR_ENTRIES] = {
#define MASK(x) [XC_FEATUREMASK_ ## x] = INIT_ ## x ## _FEATURES

        MASK(KNOWN),
        MASK(SPECIAL),
        MASK(PV_MAX),
        MASK(PV_DEF),
        MASK(HVM_SHADOW_MAX),
        MASK(HVM_SHADOW_DEF),
        MASK(HVM_HAP_MAX),
        MASK(HVM_HAP_DEF),

#undef MASK
    };

    if ( (unsigned int)mask >= ARRAY_SIZE(masks) )
        return NULL;

    return masks[mask];
}

int xc_cpu_policy_get_size(xc_interface *xch, uint32_t *nr_leaves,
                           uint32_t *nr_msrs)
{
    struct xen_sysctl sysctl = {};
    int ret;

    sysctl.cmd = XEN_SYSCTL_get_cpu_policy;

    ret = do_sysctl(xch, &sysctl);

    if ( !ret )
    {
        *nr_leaves = sysctl.u.cpu_policy.nr_leaves;
        *nr_msrs = sysctl.u.cpu_policy.nr_msrs;
    }

    return ret;
}

static int get_system_cpu_policy(xc_interface *xch, uint32_t index,
                                 uint32_t *nr_leaves, xen_cpuid_leaf_t *leaves,
                                 uint32_t *nr_msrs, xen_msr_entry_t *msrs)
{
    struct xen_sysctl sysctl = {};
    DECLARE_HYPERCALL_BOUNCE(leaves,
                             *nr_leaves * sizeof(*leaves),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BOUNCE(msrs,
                             *nr_msrs * sizeof(*msrs),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int ret;

    if ( xc_hypercall_bounce_pre(xch, leaves) ||
         xc_hypercall_bounce_pre(xch, msrs) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_get_cpu_policy;
    sysctl.u.cpu_policy.index = index;
    sysctl.u.cpu_policy.nr_leaves = *nr_leaves;
    set_xen_guest_handle(sysctl.u.cpu_policy.cpuid_policy, leaves);
    sysctl.u.cpu_policy.nr_msrs = *nr_msrs;
    set_xen_guest_handle(sysctl.u.cpu_policy.msr_policy, msrs);

    ret = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, leaves);
    xc_hypercall_bounce_post(xch, msrs);

    if ( !ret )
    {
        *nr_leaves = sysctl.u.cpu_policy.nr_leaves;
        *nr_msrs = sysctl.u.cpu_policy.nr_msrs;
    }

    return ret;
}

static int get_domain_cpu_policy(xc_interface *xch, uint32_t domid,
                                 uint32_t *nr_leaves, xen_cpuid_leaf_t *leaves,
                                 uint32_t *nr_msrs, xen_msr_entry_t *msrs)
{
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(leaves,
                             *nr_leaves * sizeof(*leaves),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BOUNCE(msrs,
                             *nr_msrs * sizeof(*msrs),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int ret;

    if ( xc_hypercall_bounce_pre(xch, leaves) ||
         xc_hypercall_bounce_pre(xch, msrs) )
        return -1;

    domctl.cmd = XEN_DOMCTL_get_cpu_policy;
    domctl.domain = domid;
    domctl.u.cpu_policy.nr_leaves = *nr_leaves;
    set_xen_guest_handle(domctl.u.cpu_policy.cpuid_policy, leaves);
    domctl.u.cpu_policy.nr_msrs = *nr_msrs;
    set_xen_guest_handle(domctl.u.cpu_policy.msr_policy, msrs);

    ret = do_domctl(xch, &domctl);

    xc_hypercall_bounce_post(xch, leaves);
    xc_hypercall_bounce_post(xch, msrs);

    if ( !ret )
    {
        *nr_leaves = domctl.u.cpu_policy.nr_leaves;
        *nr_msrs = domctl.u.cpu_policy.nr_msrs;
    }

    return ret;
}

int xc_set_domain_cpu_policy(xc_interface *xch, uint32_t domid,
                             uint32_t nr_leaves, xen_cpuid_leaf_t *leaves,
                             uint32_t nr_msrs, xen_msr_entry_t *msrs,
                             uint32_t *err_leaf_p, uint32_t *err_subleaf_p,
                             uint32_t *err_msr_p)
{
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(leaves,
                             nr_leaves * sizeof(*leaves),
                             XC_HYPERCALL_BUFFER_BOUNCE_IN);
    DECLARE_HYPERCALL_BOUNCE(msrs,
                             nr_msrs * sizeof(*msrs),
                             XC_HYPERCALL_BUFFER_BOUNCE_IN);
    int ret;

    if ( err_leaf_p )
        *err_leaf_p = -1;
    if ( err_subleaf_p )
        *err_subleaf_p = -1;
    if ( err_msr_p )
        *err_msr_p = -1;

    if ( xc_hypercall_bounce_pre(xch, leaves) )
        return -1;

    if ( xc_hypercall_bounce_pre(xch, msrs) )
        return -1;

    domctl.cmd = XEN_DOMCTL_set_cpu_policy;
    domctl.domain = domid;
    domctl.u.cpu_policy.nr_leaves = nr_leaves;
    set_xen_guest_handle(domctl.u.cpu_policy.cpuid_policy, leaves);
    domctl.u.cpu_policy.nr_msrs = nr_msrs;
    set_xen_guest_handle(domctl.u.cpu_policy.msr_policy, msrs);
    domctl.u.cpu_policy.err_leaf = -1;
    domctl.u.cpu_policy.err_subleaf = -1;
    domctl.u.cpu_policy.err_msr = -1;

    ret = do_domctl(xch, &domctl);

    xc_hypercall_bounce_post(xch, leaves);
    xc_hypercall_bounce_post(xch, msrs);

    if ( err_leaf_p )
        *err_leaf_p = domctl.u.cpu_policy.err_leaf;
    if ( err_subleaf_p )
        *err_subleaf_p = domctl.u.cpu_policy.err_subleaf;
    if ( err_msr_p )
        *err_msr_p = domctl.u.cpu_policy.err_msr;

    return ret;
}

xc_cpu_policy_t *xc_cpu_policy_init(void)
{
    return calloc(1, sizeof(struct xc_cpu_policy));
}

void xc_cpu_policy_destroy(xc_cpu_policy_t *policy)
{
    if ( policy )
        free(policy);
}

static int deserialize_policy(xc_interface *xch, xc_cpu_policy_t *policy,
                              unsigned int nr_leaves, unsigned int nr_entries)
{
    uint32_t err_leaf = -1, err_subleaf = -1, err_msr = -1;
    int rc;

    rc = x86_cpuid_copy_from_buffer(&policy->cpuid, policy->leaves,
                                    nr_leaves, &err_leaf, &err_subleaf);
    if ( rc )
    {
        if ( err_leaf != -1 )
            ERROR("Failed to deserialise CPUID (err leaf %#x, subleaf %#x) (%d = %s)",
                  err_leaf, err_subleaf, -rc, strerror(-rc));
        return rc;
    }

    rc = x86_msr_copy_from_buffer(&policy->msr, policy->entries,
                                  nr_entries, &err_msr);
    if ( rc )
    {
        if ( err_msr != -1 )
            ERROR("Failed to deserialise MSR (err MSR %#x) (%d = %s)",
                  err_msr, -rc, strerror(-rc));
        return rc;
    }

    return 0;
}

int xc_cpu_policy_get_system(xc_interface *xch, unsigned int policy_idx,
                             xc_cpu_policy_t *policy)
{
    unsigned int nr_leaves = ARRAY_SIZE(policy->leaves);
    unsigned int nr_entries = ARRAY_SIZE(policy->entries);
    int rc;

    rc = get_system_cpu_policy(xch, policy_idx, &nr_leaves, policy->leaves,
                               &nr_entries, policy->entries);
    if ( rc )
    {
        PERROR("Failed to obtain %u policy", policy_idx);
        return rc;
    }

    rc = deserialize_policy(xch, policy, nr_leaves, nr_entries);
    if ( rc )
    {
        errno = -rc;
        rc = -1;
    }

    return rc;
}

int xc_cpu_policy_get_domain(xc_interface *xch, uint32_t domid,
                             xc_cpu_policy_t *policy)
{
    unsigned int nr_leaves = ARRAY_SIZE(policy->leaves);
    unsigned int nr_entries = ARRAY_SIZE(policy->entries);
    int rc;

    rc = get_domain_cpu_policy(xch, domid, &nr_leaves, policy->leaves,
                               &nr_entries, policy->entries);
    if ( rc )
    {
        PERROR("Failed to obtain domain %u policy", domid);
        return rc;
    }

    rc = deserialize_policy(xch, policy, nr_leaves, nr_entries);
    if ( rc )
    {
        errno = -rc;
        rc = -1;
    }

    return rc;
}

int xc_cpu_policy_set_domain(xc_interface *xch, uint32_t domid,
                             xc_cpu_policy_t *policy)
{
    uint32_t err_leaf = -1, err_subleaf = -1, err_msr = -1;
    unsigned int nr_leaves = ARRAY_SIZE(policy->leaves);
    unsigned int nr_entries = ARRAY_SIZE(policy->entries);
    int rc;

    rc = xc_cpu_policy_serialise(xch, policy, policy->leaves, &nr_leaves,
                                 policy->entries, &nr_entries);
    if ( rc )
        return rc;

    rc = xc_set_domain_cpu_policy(xch, domid, nr_leaves, policy->leaves,
                                  nr_entries, policy->entries,
                                  &err_leaf, &err_subleaf, &err_msr);
    if ( rc )
    {
        ERROR("Failed to set domain %u policy (%d = %s)", domid, -rc,
              strerror(-rc));
        if ( err_leaf != -1 )
            ERROR("CPUID leaf %u subleaf %u", err_leaf, err_subleaf);
        if ( err_msr != -1 )
            ERROR("MSR index %#x\n", err_msr);
    }

    return rc;
}

int xc_cpu_policy_serialise(xc_interface *xch, const xc_cpu_policy_t *p,
                            xen_cpuid_leaf_t *leaves, uint32_t *nr_leaves,
                            xen_msr_entry_t *msrs, uint32_t *nr_msrs)
{
    int rc;

    if ( leaves )
    {
        rc = x86_cpuid_copy_to_buffer(&p->cpuid, leaves, nr_leaves);
        if ( rc )
        {
            ERROR("Failed to serialize CPUID policy");
            errno = -rc;
            return -1;
        }
    }

    if ( msrs )
    {
        rc = x86_msr_copy_to_buffer(&p->msr, msrs, nr_msrs);
        if ( rc )
        {
            ERROR("Failed to serialize MSR policy");
            errno = -rc;
            return -1;
        }
    }

    errno = 0;
    return 0;
}

int xc_cpu_policy_update_cpuid(xc_interface *xch, xc_cpu_policy_t *policy,
                               const xen_cpuid_leaf_t *leaves,
                               uint32_t nr)
{
    unsigned int err_leaf = -1, err_subleaf = -1;
    int rc = x86_cpuid_copy_from_buffer(&policy->cpuid, leaves, nr,
                                        &err_leaf, &err_subleaf);

    if ( rc )
    {
        if ( err_leaf != -1 )
            ERROR("Failed to update CPUID (err leaf %#x, subleaf %#x) (%d = %s)",
                  err_leaf, err_subleaf, -rc, strerror(-rc));
        errno = -rc;
        rc = -1;
    }

    return rc;
}

int xc_cpu_policy_update_msrs(xc_interface *xch, xc_cpu_policy_t *policy,
                              const xen_msr_entry_t *msrs, uint32_t nr)
{
    unsigned int err_msr = -1;
    int rc = x86_msr_copy_from_buffer(&policy->msr, msrs, nr, &err_msr);

    if ( rc )
    {
        if ( err_msr != -1 )
            ERROR("Failed to deserialise MSRS (err index %#x) (%d = %s)",
                  err_msr, -rc, strerror(-rc));
        errno = -rc;
        rc = -1;
    }

    return rc;
}

int xc_cpu_policy_get_cpuid(xc_interface *xch, const xc_cpu_policy_t *policy,
                            uint32_t leaf, uint32_t subleaf,
                            xen_cpuid_leaf_t *out)
{
    const struct cpuid_leaf *tmp;

    *out = (xen_cpuid_leaf_t){};

    tmp = x86_cpuid_get_leaf(&policy->cpuid, leaf, subleaf);
    if ( !tmp )
    {
        /* Unable to find a matching leaf. */
        errno = ENOENT;
        return -1;
    }

    out->leaf = leaf;
    out->subleaf = subleaf;
    out->a = tmp->a;
    out->b = tmp->b;
    out->c = tmp->c;
    out->d = tmp->d;

    return 0;
}

int xc_cpu_policy_get_msr(xc_interface *xch, const xc_cpu_policy_t *policy,
                          uint32_t msr, xen_msr_entry_t *out)
{
    const uint64_t *val;

    *out = (xen_msr_entry_t){};

    val = x86_msr_get_entry(&policy->msr, msr);
    if ( !val )
    {
        errno = ENOENT;
        return -1;
    }

    out->idx = msr;
    out->val = *val;

    return 0;
}

bool xc_cpu_policy_is_compatible(xc_interface *xch, xc_cpu_policy_t *host,
                                 xc_cpu_policy_t *guest)
{
    struct cpu_policy_errors err = INIT_CPU_POLICY_ERRORS;
    struct cpu_policy h = { &host->cpuid, &host->msr };
    struct cpu_policy g = { &guest->cpuid, &guest->msr };
    int rc = x86_cpu_policies_are_compatible(&h, &g, &err);

    if ( !rc )
        return true;

    if ( err.leaf != -1 )
        ERROR("Leaf %#x subleaf %#x is not compatible", err.leaf, err.subleaf);
    if ( err.msr != -1 )
        ERROR("MSR index %#x is not compatible", err.msr);

    return false;
}

void xc_cpu_policy_make_compat_4_12(xc_interface *xch, xc_cpu_policy_t *policy,
                                    const xc_cpu_policy_t *host, bool hvm)
{
    /*
     * Account for features which have been disabled by default since Xen 4.13,
     * so migrated-in VM's don't risk seeing features disappearing.
     */
    policy->cpuid.basic.rdrand = host->cpuid.basic.rdrand;
    policy->cpuid.feat.hle = host->cpuid.feat.hle;
    policy->cpuid.feat.rtm = host->cpuid.feat.rtm;

    if ( hvm )
        policy->cpuid.feat.mpx = host->cpuid.feat.mpx;

    /* Clamp maximum leaves to the ones supported on pre-4.13. */
    policy->cpuid.basic.max_leaf = min(policy->cpuid.basic.max_leaf, 0xdu);
    policy->cpuid.feat.max_subleaf = 0;
    policy->cpuid.extd.max_leaf = min(policy->cpuid.extd.max_leaf, 0x8000001c);
}

void xc_cpu_policy_legacy_topology(xc_interface *xch, xc_cpu_policy_t *policy,
                                   const xc_cpu_policy_t *host)
{
    if ( host )
    {
        /*
         * On hardware without CPUID Faulting, PV guests see real topology.
         * As a consequence, they also need to see the host htt/cmp fields.
         */
        policy->cpuid.basic.htt = host->cpuid.basic.htt;
        policy->cpuid.extd.cmp_legacy = host->cpuid.extd.cmp_legacy;
    }
    else
    {
        unsigned int i;

        /*
         * Topology for HVM guests is entirely controlled by Xen.  For now, we
         * hardcode APIC_ID = vcpu_id * 2 to give the illusion of no SMT.
         */
        policy->cpuid.basic.htt = true;
        policy->cpuid.extd.cmp_legacy = false;

        /*
         * Leaf 1 EBX[23:16] is Maximum Logical Processors Per Package.
         * Update to reflect vLAPIC_ID = vCPU_ID * 2, but make sure to avoid
         * overflow.
         */
        if ( !policy->cpuid.basic.lppp )
            policy->cpuid.basic.lppp = 2;
        else if ( !(policy->cpuid.basic.lppp & 0x80) )
            policy->cpuid.basic.lppp *= 2;

        switch ( policy->cpuid.x86_vendor )
        {
        case X86_VENDOR_INTEL:
            for ( i = 0; (policy->cpuid.cache.subleaf[i].type &&
                          i < ARRAY_SIZE(policy->cpuid.cache.raw)); ++i )
            {
                policy->cpuid.cache.subleaf[i].cores_per_package =
                  (policy->cpuid.cache.subleaf[i].cores_per_package << 1) | 1;
                policy->cpuid.cache.subleaf[i].threads_per_cache = 0;
            }
            break;

        case X86_VENDOR_AMD:
        case X86_VENDOR_HYGON:
            /*
             * Leaf 0x80000008 ECX[15:12] is ApicIdCoreSize.
             * Leaf 0x80000008 ECX[7:0] is NumberOfCores (minus one).
             * Update to reflect vLAPIC_ID = vCPU_ID * 2.  But avoid
             * - overflow,
             * - going out of sync with leaf 1 EBX[23:16],
             * - incrementing ApicIdCoreSize when it's zero (which changes the
             *   meaning of bits 7:0).
             *
             * UPDATE: In addition to avoiding overflow, some
             * proprietary operating systems have trouble with
             * apic_id_size values greater than 7.  Limit the value to
             * 7 for now.
             */
            if ( policy->cpuid.extd.nc < 0x7f )
            {
                if ( policy->cpuid.extd.apic_id_size != 0 &&
                     policy->cpuid.extd.apic_id_size < 0x7 )
                    policy->cpuid.extd.apic_id_size++;

                policy->cpuid.extd.nc = (policy->cpuid.extd.nc << 1) | 1;
            }
            break;
        }
    }
}

int xc_cpu_policy_apply_featureset(xc_interface *xch, xc_cpu_policy_t *policy,
                                   const uint32_t *featureset,
                                   unsigned int nr_features)
{
    uint32_t disabled_features[FEATURESET_NR_ENTRIES],
        feat[FEATURESET_NR_ENTRIES] = {};
    static const uint32_t deep_features[] = INIT_DEEP_FEATURES;
    unsigned int i, b;

    /*
     * The user supplied featureset may be shorter or longer than
     * FEATURESET_NR_ENTRIES.  Shorter is fine, and we will zero-extend.
     * Longer is fine, so long as it only padded with zeros.
     */
    unsigned int user_len = min(FEATURESET_NR_ENTRIES + 0u, nr_features);

    /* Check for truncated set bits. */
    for ( i = user_len; i < nr_features; ++i )
        if ( featureset[i] != 0 )
        {
            errno = EOPNOTSUPP;
            return -1;
        }

    memcpy(feat, featureset, sizeof(*featureset) * user_len);

    /* Disable deep dependencies of disabled features. */
    for ( i = 0; i < ARRAY_SIZE(disabled_features); ++i )
        disabled_features[i] = ~feat[i] & deep_features[i];

    for ( b = 0; b < sizeof(disabled_features) * CHAR_BIT; ++b )
    {
        const uint32_t *dfs;

        if ( !test_bit(b, disabled_features) ||
             !(dfs = x86_cpuid_lookup_deep_deps(b)) )
            continue;

        for ( i = 0; i < ARRAY_SIZE(disabled_features); ++i )
        {
            feat[i] &= ~dfs[i];
            disabled_features[i] &= ~dfs[i];
        }
    }

    cpuid_featureset_to_policy(feat, &policy->cpuid);

    return 0;
}
