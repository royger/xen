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
#include "xc_private.h"
#include "xc_bitops.h"
#include <xen/hvm/params.h>
#include <xen-tools/libs.h>

enum {
#define XEN_CPUFEATURE(name, value) X86_FEATURE_##name = value,
#include <xen/arch-x86/cpufeatureset.h>
};

#include <xen/asm/msr-index.h>
#include <xen/asm/x86-vendors.h>

#include <xen/lib/x86/cpu-policy.h>

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

static int set_domain_cpu_policy(xc_interface *xch, uint32_t domid,
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

int xc_cpu_policy_apply_cpuid(xc_interface *xch, xc_cpu_policy_t policy,
                              const struct xc_xend_cpuid *cpuid, bool hvm)
{
    int rc;
    xc_cpu_policy_t host = NULL, max = NULL;

    host = xc_cpu_policy_init();
    max = xc_cpu_policy_init();
    if ( !host || !max )
    {
        PERROR("Failed to init policies");
        rc = -ENOMEM;
        goto out;
    }

    /* Get the domain's max policy. */
    rc = xc_cpu_policy_get_system(xch, hvm ? XEN_SYSCTL_cpu_policy_hvm_max
                                           : XEN_SYSCTL_cpu_policy_pv_max,
                                  max);
    if ( rc )
    {
        PERROR("Failed to obtain %s max policy", hvm ? "hvm" : "pv");
        goto out;
    }

    /* Get the host policy. */
    rc = xc_cpu_policy_get_system(xch, XEN_SYSCTL_cpu_policy_host, host);
    if ( rc )
    {
        PERROR("Failed to obtain host policy");
        goto out;
    }

    rc = -EINVAL;
    for ( ; cpuid->leaf != XEN_CPUID_INPUT_UNUSED; ++cpuid )
    {
        xen_cpuid_leaf_t cur_leaf;
        xen_cpuid_leaf_t max_leaf;
        xen_cpuid_leaf_t host_leaf;

        rc = xc_cpu_policy_get_cpuid(xch, policy, cpuid->leaf, cpuid->subleaf,
                                     &cur_leaf);
        if ( rc )
        {
            ERROR("Failed to get current policy leaf %#x subleaf %#x",
                  cpuid->leaf, cpuid->subleaf);
            goto out;
        }
        rc = xc_cpu_policy_get_cpuid(xch, max, cpuid->leaf, cpuid->subleaf,
                                     &max_leaf);
        if ( rc )
        {
            ERROR("Failed to get max policy leaf %#x subleaf %#x",
                  cpuid->leaf, cpuid->subleaf);
            goto out;
        }
        rc = xc_cpu_policy_get_cpuid(xch, host, cpuid->leaf, cpuid->subleaf,
                                     &host_leaf);
        if ( rc )
        {
            ERROR("Failed to get host policy leaf %#x subleaf %#x",
                  cpuid->leaf, cpuid->subleaf);
            goto out;
        }

        for ( unsigned int i = 0; i < ARRAY_SIZE(cpuid->policy); i++ )
        {
            uint32_t *cur_reg = &cur_leaf.a + i;
            const uint32_t *max_reg = &max_leaf.a + i;
            const uint32_t *host_reg = &host_leaf.a + i;

            if ( cpuid->policy[i] == NULL )
                continue;

            for ( unsigned int j = 0; j < 32; j++ )
            {
                bool val;

                switch ( cpuid->policy[i][j] )
                {
                case '1':
                    val = true;
                    break;

                case '0':
                    val = false;
                    break;

                case 'x':
                    val = test_bit(31 - j, max_reg);
                    break;

                case 'k':
                case 's':
                    val = test_bit(31 - j, host_reg);
                    break;

                default:
                    ERROR("Bad character '%c' in policy[%d] string '%s'",
                          cpuid->policy[i][j], i, cpuid->policy[i]);
                    goto out;
                }

                clear_bit(31 - j, cur_reg);
                if ( val )
                    set_bit(31 - j, cur_reg);
            }
        }

        rc = xc_cpu_policy_update_cpuid(xch, policy, &cur_leaf, 1);
        if ( rc )
        {
            PERROR("Failed to set policy leaf %#x subleaf %#x",
                   cpuid->leaf, cpuid->subleaf);
            goto out;
        }
    }

 out:
    xc_cpu_policy_destroy(max);
    xc_cpu_policy_destroy(host);

    return rc;
}

int xc_cpuid_apply_policy(xc_interface *xch, uint32_t domid, bool restore,
                          const uint32_t *featureset, unsigned int nr_features,
                          bool pae, bool itsc, bool nested_virt,
                          const struct xc_xend_cpuid *cpuid)
{
    int rc;
    xc_dominfo_t di;
    unsigned int nr_leaves, nr_msrs;
    xen_cpuid_leaf_t *leaves = NULL;
    struct cpuid_policy *p = NULL;
    struct cpu_policy policy = { };
    uint32_t err_leaf = -1, err_subleaf = -1, err_msr = -1;

    if ( xc_domain_getinfo(xch, domid, 1, &di) != 1 ||
         di.domid != domid )
    {
        ERROR("Failed to obtain d%d info", domid);
        rc = -ESRCH;
        goto out;
    }

    rc = xc_cpu_policy_get_size(xch, &nr_leaves, &nr_msrs);
    if ( rc )
    {
        PERROR("Failed to obtain policy info size");
        rc = -errno;
        goto out;
    }

    rc = -ENOMEM;
    if ( (leaves = calloc(nr_leaves, sizeof(*leaves))) == NULL ||
         (p = calloc(1, sizeof(*p))) == NULL )
        goto out;

    /* Get the domain's default policy. */
    nr_msrs = 0;
    rc = get_system_cpu_policy(xch, di.hvm ? XEN_SYSCTL_cpu_policy_hvm_default
                                           : XEN_SYSCTL_cpu_policy_pv_default,
                               &nr_leaves, leaves, &nr_msrs, NULL);
    if ( rc )
    {
        PERROR("Failed to obtain %s default policy", di.hvm ? "hvm" : "pv");
        rc = -errno;
        goto out;
    }

    rc = x86_cpuid_copy_from_buffer(p, leaves, nr_leaves,
                                    &err_leaf, &err_subleaf);
    if ( rc )
    {
        ERROR("Failed to deserialise CPUID (err leaf %#x, subleaf %#x) (%d = %s)",
              err_leaf, err_subleaf, -rc, strerror(-rc));
        goto out;
    }

    /*
     * Account for feature which have been disabled by default since Xen 4.13,
     * so migrated-in VM's don't risk seeing features disappearing.
     */
    if ( restore )
    {
        policy.cpuid = p;
        xc_cpu_policy_make_compatible(xch, &policy, di.hvm);
    }

    if ( featureset )
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
        rc = -EOPNOTSUPP;
        for ( i = user_len; i < nr_features; ++i )
            if ( featureset[i] != 0 )
                goto out;

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

        cpuid_featureset_to_policy(feat, p);
    }
    else
    {
        p->extd.itsc = itsc;

        if ( di.hvm )
        {
            p->basic.pae = pae;
            p->basic.vmx = nested_virt;
            p->extd.svm = nested_virt;
        }
    }

    policy.cpuid = p;
    rc = xc_cpu_policy_topology(xch, &policy, di.hvm);
    if ( rc )
        goto out;

    rc = xc_cpu_policy_apply_cpuid(xch, &policy, cpuid, di.hvm);
    if ( rc )
        goto out;

    rc = x86_cpuid_copy_to_buffer(p, leaves, &nr_leaves);
    if ( rc )
    {
        ERROR("Failed to serialise CPUID (%d = %s)", -rc, strerror(-rc));
        goto out;
    }

    rc = set_domain_cpu_policy(xch, domid, nr_leaves, leaves, 0, NULL,
                               &err_leaf, &err_subleaf, &err_msr);
    if ( rc )
    {
        PERROR("Failed to set d%d's policy (err leaf %#x, subleaf %#x, msr %#x)",
               domid, err_leaf, err_subleaf, err_msr);
        rc = -errno;
        goto out;
    }

    rc = 0;

out:
    free(p);
    free(leaves);

    return rc;
}

xc_cpu_policy_t xc_cpu_policy_init(void)
{
    xc_cpu_policy_t policy = calloc(1, sizeof(*policy));

    if ( !policy )
        return NULL;

    policy->cpuid = calloc(1, sizeof(*policy->cpuid));
    policy->msr = calloc(1, sizeof(*policy->msr));
    if ( !policy->cpuid || !policy->msr )
    {
        xc_cpu_policy_destroy(policy);
        return NULL;
    }

    return policy;
}

void xc_cpu_policy_destroy(xc_cpu_policy_t policy)
{
    if ( !policy )
        return;

    free(policy->cpuid);
    free(policy->msr);
    free(policy);
}

static int allocate_buffers(xc_interface *xch,
                            unsigned int *nr_leaves, xen_cpuid_leaf_t **leaves,
                            unsigned int *nr_msrs, xen_msr_entry_t **msrs)
{
    int rc;

    *leaves = NULL;
    *msrs = NULL;

    rc = xc_cpu_policy_get_size(xch, nr_leaves, nr_msrs);
    if ( rc )
    {
        PERROR("Failed to obtain policy info size");
        return -errno;
    }

    *leaves = calloc(*nr_leaves, sizeof(**leaves));
    *msrs = calloc(*nr_msrs, sizeof(**msrs));
    if ( !*leaves || !*msrs )
    {
        PERROR("Failed to allocate resources");
        free(*leaves);
        free(*msrs);
        return -ENOMEM;
    }

    return 0;
}

static int deserialize_policy(xc_interface *xch, xc_cpu_policy_t policy,
                              unsigned int nr_leaves,
                              const xen_cpuid_leaf_t *leaves,
                              unsigned int nr_msrs, const xen_msr_entry_t *msrs)
{
    uint32_t err_leaf = -1, err_subleaf = -1, err_msr = -1;
    int rc;

    rc = x86_cpuid_copy_from_buffer(policy->cpuid, leaves, nr_leaves,
                                    &err_leaf, &err_subleaf);
    if ( rc )
    {
        ERROR("Failed to deserialise CPUID (err leaf %#x, subleaf %#x) (%d = %s)",
              err_leaf, err_subleaf, -rc, strerror(-rc));
        return rc;
    }

    rc = x86_msr_copy_from_buffer(policy->msr, msrs, nr_msrs, &err_msr);
    if ( rc )
    {
        ERROR("Failed to deserialise MSR (err MSR %#x) (%d = %s)",
              err_msr, -rc, strerror(-rc));
        return rc;
    }

    return 0;
}

int xc_cpu_policy_get_system(xc_interface *xch, unsigned int idx,
                             xc_cpu_policy_t policy)
{
    unsigned int nr_leaves, nr_msrs;
    xen_cpuid_leaf_t *leaves = NULL;
    xen_msr_entry_t *msrs = NULL;
    int rc;

    rc = allocate_buffers(xch, &nr_leaves, &leaves, &nr_msrs, &msrs);
    if ( rc )
    {
        errno = -rc;
        return -1;
    }

    rc = get_system_cpu_policy(xch, idx, &nr_leaves, leaves, &nr_msrs, msrs);
    if ( rc )
    {
        PERROR("Failed to obtain %u policy", idx);
        rc = -1;
        goto out;
    }

    rc = deserialize_policy(xch, policy, nr_leaves, leaves, nr_msrs, msrs);
    if ( rc )
    {
        errno = -rc;
        rc = -1;
    }

 out:
    free(leaves);
    free(msrs);
    return rc;
}

int xc_cpu_policy_get_domain(xc_interface *xch, uint32_t domid,
                             xc_cpu_policy_t policy)
{
    unsigned int nr_leaves, nr_msrs;
    xen_cpuid_leaf_t *leaves = NULL;
    xen_msr_entry_t *msrs = NULL;
    int rc;

    rc = allocate_buffers(xch, &nr_leaves, &leaves, &nr_msrs, &msrs);
    if ( rc )
    {
        errno = -rc;
        return -1;
    }

    rc = get_domain_cpu_policy(xch, domid, &nr_leaves, leaves, &nr_msrs,
                               msrs);
    if ( rc )
    {
        PERROR("Failed to obtain domain %u policy", domid);
        rc = -1;
        goto out;
    }

    rc = deserialize_policy(xch, policy, nr_leaves, leaves, nr_msrs, msrs);
    if ( rc )
    {
        errno = -rc;
        rc = -1;
    }

 out:
    free(leaves);
    free(msrs);
    return rc;
}

int xc_cpu_policy_set_domain(xc_interface *xch, uint32_t domid,
                             const xc_cpu_policy_t policy)
{
    uint32_t err_leaf = -1, err_subleaf = -1, err_msr = -1;
    unsigned int nr_leaves, nr_msrs;
    xen_cpuid_leaf_t *leaves = NULL;
    xen_msr_entry_t *msrs = NULL;
    int rc;

    rc = allocate_buffers(xch, &nr_leaves, &leaves, &nr_msrs, &msrs);
    if ( rc )
    {
        errno = -rc;
        return -1;
    }

    rc = xc_cpu_policy_serialise(xch, policy, leaves, &nr_leaves,
                                 msrs, &nr_msrs);
    if ( rc )
        goto out;

    rc = set_domain_cpu_policy(xch, domid, nr_leaves, leaves, nr_msrs, msrs,
                               &err_leaf, &err_subleaf, &err_msr);
    if ( rc )
    {
        ERROR("Failed to set domain %u policy (%d = %s)", domid, -rc,
              strerror(-rc));
        if ( err_leaf != -1 )
            ERROR("CPUID leaf %u subleaf %u", err_leaf, err_subleaf);
        if ( err_msr != -1 )
            ERROR("MSR index %#x\n", err_msr);
        goto out;
    }

 out:
    free(leaves);
    free(msrs);
    return rc;
}

int xc_cpu_policy_serialise(xc_interface *xch, const xc_cpu_policy_t p,
                            xen_cpuid_leaf_t *leaves, uint32_t *nr_leaves,
                            xen_msr_entry_t *msrs, uint32_t *nr_msrs)
{
    int rc;

    if ( leaves )
    {
        rc = x86_cpuid_copy_to_buffer(p->cpuid, leaves, nr_leaves);
        if ( rc )
        {
            ERROR("Failed to serialize CPUID policy");
            errno = -rc;
            return -1;
        }
    }

    if ( msrs )
    {
        rc = x86_msr_copy_to_buffer(p->msr, msrs, nr_msrs);
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

int xc_cpu_policy_get_cpuid(xc_interface *xch, const xc_cpu_policy_t policy,
                            uint32_t leaf, uint32_t subleaf,
                            xen_cpuid_leaf_t *out)
{
    unsigned int nr_leaves, nr_msrs, i;
    xen_cpuid_leaf_t *leaves;
    int rc = xc_cpu_policy_get_size(xch, &nr_leaves, &nr_msrs);

    if ( rc )
    {
        PERROR("Failed to obtain policy info size");
        return -1;
    }

    leaves = calloc(nr_leaves, sizeof(*leaves));
    if ( !leaves )
    {
        PERROR("Failed to allocate resources");
        errno = ENOMEM;
        return -1;
    }

    rc = xc_cpu_policy_serialise(xch, policy, leaves, &nr_leaves, NULL, 0);
    if ( rc )
        goto out;

    for ( i = 0; i < nr_leaves; i++ )
        if ( leaves[i].leaf == leaf && leaves[i].subleaf == subleaf )
        {
            *out = leaves[i];
            goto out;
        }

    /* Unable to find a matching leaf. */
    errno = ENOENT;
    rc = -1;

 out:
    free(leaves);
    return rc;
}

int xc_cpu_policy_get_msr(xc_interface *xch, const xc_cpu_policy_t policy,
                          uint32_t msr, xen_msr_entry_t *out)
{
    unsigned int nr_leaves, nr_msrs, i;
    xen_msr_entry_t *msrs;
    int rc = xc_cpu_policy_get_size(xch, &nr_leaves, &nr_msrs);

    if ( rc )
    {
        PERROR("Failed to obtain policy info size");
        return -1;
    }

    msrs = calloc(nr_msrs, sizeof(*msrs));
    if ( !msrs )
    {
        PERROR("Failed to allocate resources");
        errno = ENOMEM;
        return -1;
    }

    rc = xc_cpu_policy_serialise(xch, policy, NULL, 0, msrs, &nr_msrs);
    if ( rc )
        goto out;

    for ( i = 0; i < nr_msrs; i++ )
        if ( msrs[i].idx == msr )
        {
            *out = msrs[i];
            goto out;
        }

    /* Unable to find a matching MSR. */
    errno = ENOENT;
    rc = -1;

 out:
    free(msrs);
    return rc;
}

int xc_cpu_policy_update_cpuid(xc_interface *xch, xc_cpu_policy_t policy,
                               const xen_cpuid_leaf_t *leaves,
                               uint32_t nr)
{
    unsigned int err_leaf = -1, err_subleaf = -1;
    unsigned int nr_leaves, nr_msrs, i, j;
    xen_cpuid_leaf_t *current;
    int rc = xc_cpu_policy_get_size(xch, &nr_leaves, &nr_msrs);

    if ( rc )
    {
        PERROR("Failed to obtain policy info size");
        return -1;
    }

    current = calloc(nr_leaves, sizeof(*current));
    if ( !current )
    {
        PERROR("Failed to allocate resources");
        errno = ENOMEM;
        return -1;
    }

    rc = xc_cpu_policy_serialise(xch, policy, current, &nr_leaves, NULL, 0);
    if ( rc )
        goto out;

    for ( i = 0; i < nr; i++ )
    {
        const xen_cpuid_leaf_t *update = &leaves[i];

        for ( j = 0; j < nr_leaves; j++ )
            if ( current[j].leaf == update->leaf &&
                 current[j].subleaf == update->subleaf )
            {
                current[j] = *update;
                break;
            }

        if ( j == nr_leaves )
        {
            /* Failed to find a matching leaf, append to the end. */
            current = realloc(current, (nr_leaves + 1) * sizeof(*current));
            memcpy(&current[nr_leaves], update, sizeof(*update));
            nr_leaves++;
        }
    }

    rc = x86_cpuid_copy_from_buffer(policy->cpuid, current, nr_leaves,
                                    &err_leaf, &err_subleaf);
    if ( rc )
    {
        ERROR("Failed to deserialise CPUID (err leaf %#x, subleaf %#x) (%d = %s)",
              err_leaf, err_subleaf, -rc, strerror(-rc));
        errno = -rc;
        rc = -1;
    }

 out:
    free(current);
    return rc;
}

int xc_cpu_policy_update_msrs(xc_interface *xch, xc_cpu_policy_t policy,
                              const xen_msr_entry_t *msrs, uint32_t nr)
{
    unsigned int err_msr = -1;
    unsigned int nr_leaves, nr_msrs, i, j;
    xen_msr_entry_t *current;
    int rc = xc_cpu_policy_get_size(xch, &nr_leaves, &nr_msrs);

    if ( rc )
    {
        PERROR("Failed to obtain policy info size");
        return -1;
    }

    current = calloc(nr_msrs, sizeof(*current));
    if ( !current )
    {
        PERROR("Failed to allocate resources");
        errno = ENOMEM;
        return -1;
    }

    rc = xc_cpu_policy_serialise(xch, policy, NULL, 0, current, &nr_msrs);
    if ( rc )
        goto out;

    for ( i = 0; i < nr; i++ )
    {
        const xen_msr_entry_t *update = &msrs[i];

        for ( j = 0; j < nr_msrs; j++ )
            if ( current[j].idx == update->idx )
            {
                /*
                 * NB: cannot use an assignation because of the const vs
                 * non-const difference.
                 */
                memcpy(&current[j], update, sizeof(*update));
                break;
            }

        if ( j == nr_msrs )
        {
            /* Failed to find a matching MSR, append to the end. */
            current = realloc(current, (nr_msrs + 1) * sizeof(*current));
            memcpy(&current[nr_msrs], update, sizeof(*update));
            nr_msrs++;
        }
    }

    rc = x86_msr_copy_from_buffer(policy->msr, current, nr_msrs, &err_msr);
    if ( rc )
    {
        ERROR("Failed to deserialise MSRS (err index %#x) (%d = %s)",
              err_msr, -rc, strerror(-rc));
        errno = -rc;
        rc = -1;
    }

 out:
    free(current);
    return rc;

}

bool xc_cpu_policy_is_compatible(xc_interface *xch, const xc_cpu_policy_t p1,
                                 const xc_cpu_policy_t p2)
{
    struct cpu_policy_errors err = INIT_CPU_POLICY_ERRORS;
    int rc = x86_cpu_policies_are_compatible(p1, p2, &err);

    if ( !rc )
        return true;

    if ( err.leaf != -1 )
        ERROR("Leaf %#x subleaf %#x is not compatible", err.leaf, err.subleaf);
    if ( err.msr != -1 )
        ERROR("MSR index %#x is not compatible", err.msr);

    return false;
}

static uint64_t level_msr(unsigned int index, uint64_t val1, uint64_t val2)
{
    uint64_t val;

    switch( index )
    {
    case MSR_ARCH_CAPABILITIES:
        val = val1 & val2;
        /*
         * Set RSBA if present on any of the input values to notice the guest
         * might run on vulnerable hardware at some point.
         */
        val |= (val1 | val2) & ARCH_CAPS_RSBA;
        break;

    default:
        val = val1 & val2;
        break;
    }

    return val;
}

int xc_cpu_policy_calc_compatible(xc_interface *xch,
                                  const xc_cpu_policy_t p1,
                                  const xc_cpu_policy_t p2,
                                  xc_cpu_policy_t out)
{
    xen_cpuid_leaf_t *leaves = NULL, *p1_leaves = NULL, *p2_leaves = NULL;
    xen_msr_entry_t *msrs = NULL, *p1_msrs = NULL, *p2_msrs = NULL;
    unsigned int nr_leaves, nr_msrs, i, j, index;
    unsigned int p1_nr_leaves, p1_nr_msrs, p2_nr_leaves, p2_nr_msrs;
    int rc;

    if ( xc_cpu_policy_get_size(xch, &nr_leaves, &nr_msrs) )
    {
        PERROR("Failed to obtain policy info size");
        return -1;
    }

    leaves = calloc(nr_leaves, sizeof(*leaves));
    p1_leaves = calloc(nr_leaves, sizeof(*p1_leaves));
    p2_leaves = calloc(nr_leaves, sizeof(*p2_leaves));
    msrs = calloc(nr_msrs, sizeof(*msrs));
    p1_msrs = calloc(nr_msrs, sizeof(*p1_msrs));
    p2_msrs = calloc(nr_msrs, sizeof(*p2_msrs));

    p1_nr_leaves = p2_nr_leaves = nr_leaves;
    p1_nr_msrs = p2_nr_msrs = nr_msrs;

    if ( !leaves || !p1_leaves || !p2_leaves ||
         !msrs || !p1_msrs || !p2_msrs )
    {
        ERROR("Failed to allocate resources");
        errno = ENOMEM;
        rc = -1;
        goto out;
    }

    rc = xc_cpu_policy_serialise(xch, p1, p1_leaves, &p1_nr_leaves,
                                 p1_msrs, &p1_nr_msrs);
    if ( rc )
        goto out;
    rc = xc_cpu_policy_serialise(xch, p2, p2_leaves, &p2_nr_leaves,
                                 p2_msrs, &p2_nr_msrs);
    if ( rc )
        goto out;

    index = 0;
    for ( i = 0; i < p1_nr_leaves; i++ )
        for ( j = 0; j < p2_nr_leaves; j++ )
            if ( p1_leaves[i].leaf == p2_leaves[j].leaf &&
                 p1_leaves[i].subleaf == p2_leaves[j].subleaf )
            {
                leaves[index].leaf = p1_leaves[i].leaf;
                leaves[index].subleaf = p1_leaves[i].subleaf;
                leaves[index].a = p1_leaves[i].a & p2_leaves[j].a;
                leaves[index].b = p1_leaves[i].b & p2_leaves[j].b;
                leaves[index].c = p1_leaves[i].c & p2_leaves[j].c;
                leaves[index].d = p1_leaves[i].d & p2_leaves[j].d;
                index++;
            }
    nr_leaves = index;

    index = 0;
    for ( i = 0; i < p1_nr_msrs; i++ )
        for ( j = 0; j < p2_nr_msrs; j++ )
            if ( p1_msrs[i].idx == p2_msrs[j].idx )
            {
                msrs[index].idx = p1_msrs[i].idx;
                msrs[index].val = level_msr(p1_msrs[i].idx,
                                            p1_msrs[i].val, p2_msrs[j].val);
                index++;
            }
    nr_msrs = index;

    rc = deserialize_policy(xch, out, nr_leaves, leaves, nr_msrs, msrs);
    if ( rc )
    {
        errno = -rc;
        rc = -1;
    }

 out:
    free(leaves);
    free(p1_leaves);
    free(p2_leaves);
    free(msrs);
    free(p1_msrs);
    free(p2_msrs);

    return rc;
}

int xc_cpu_policy_make_compatible(xc_interface *xch, xc_cpu_policy_t policy,
                                  bool hvm)
{
    xc_cpu_policy_t host;
    int rc;

    host = xc_cpu_policy_init();
    if ( !host )
    {
        errno = ENOMEM;
        return -1;
    }

    rc = xc_cpu_policy_get_system(xch, XEN_SYSCTL_cpu_policy_host, host);
    if ( rc )
    {
        ERROR("Failed to get host policy");
        goto out;
    }

    policy->cpuid->basic.rdrand = host->cpuid->basic.rdrand;

    if ( hvm )
        policy->cpuid->feat.mpx = host->cpuid->feat.mpx;

 out:
    xc_cpu_policy_destroy(host);
    return rc;
}

int xc_cpu_policy_topology(xc_interface *xch, xc_cpu_policy_t policy,
                           bool hvm)
{
    if ( !hvm )
    {
        xc_cpu_policy_t host;
        int rc;

        host = xc_cpu_policy_init();
        if ( !host )
        {
            errno = ENOMEM;
            return -1;
        }

        rc = xc_cpu_policy_get_system(xch, XEN_SYSCTL_cpu_policy_host, host);
        if ( rc )
        {
            ERROR("Failed to get host policy");
            xc_cpu_policy_destroy(host);
            return rc;
        }


        /*
         * On hardware without CPUID Faulting, PV guests see real topology.
         * As a consequence, they also need to see the host htt/cmp fields.
         */
        policy->cpuid->basic.htt = host->cpuid->basic.htt;
        policy->cpuid->extd.cmp_legacy = host->cpuid->extd.cmp_legacy;
    }
    else
    {
        unsigned int i;

        /*
         * Topology for HVM guests is entirely controlled by Xen.  For now, we
         * hardcode APIC_ID = vcpu_id * 2 to give the illusion of no SMT.
         */
        policy->cpuid->basic.htt = true;
        policy->cpuid->extd.cmp_legacy = false;

        /*
         * Leaf 1 EBX[23:16] is Maximum Logical Processors Per Package.
         * Update to reflect vLAPIC_ID = vCPU_ID * 2, but make sure to avoid
         * overflow.
         */
        if ( !(policy->cpuid->basic.lppp & 0x80) )
            policy->cpuid->basic.lppp *= 2;

        switch ( policy->cpuid->x86_vendor )
        {
        case X86_VENDOR_INTEL:
            for ( i = 0; (policy->cpuid->cache.subleaf[i].type &&
                          i < ARRAY_SIZE(policy->cpuid->cache.raw)); ++i )
            {
                policy->cpuid->cache.subleaf[i].cores_per_package =
                  (policy->cpuid->cache.subleaf[i].cores_per_package << 1) | 1;
                policy->cpuid->cache.subleaf[i].threads_per_cache = 0;
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
             * UPDATE: I addition to avoiding overflow, some
             * proprietary operating systems have trouble with
             * apic_id_size values greater than 7.  Limit the value to
             * 7 for now.
             */
            if ( policy->cpuid->extd.nc < 0x7f )
            {
                if ( policy->cpuid->extd.apic_id_size != 0 &&
                     policy->cpuid->extd.apic_id_size < 0x7 )
                    policy->cpuid->extd.apic_id_size++;

                policy->cpuid->extd.nc = (policy->cpuid->extd.nc << 1) | 1;
            }
            break;
        }
    }

    return 0;
}
