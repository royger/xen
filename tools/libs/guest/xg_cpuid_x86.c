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

struct xc_cpu_policy {
    struct cpuid_policy cpuid;
    struct msr_policy msr;
    xen_cpuid_leaf_t leaves[CPUID_MAX_SERIALISED_LEAVES];
    xen_msr_entry_t entries[MSR_MAX_SERIALISED_ENTRIES];
};

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

static int compare_leaves(const void *l, const void *r)
{
    const xen_cpuid_leaf_t *lhs = l;
    const xen_cpuid_leaf_t *rhs = r;

    if ( lhs->leaf != rhs->leaf )
        return lhs->leaf < rhs->leaf ? -1 : 1;

    if ( lhs->subleaf != rhs->subleaf )
        return lhs->subleaf < rhs->subleaf ? -1 : 1;

    return 0;
}

static xen_cpuid_leaf_t *find_leaf(
    xen_cpuid_leaf_t *leaves, unsigned int nr_leaves,
    unsigned int leaf, unsigned int subleaf)
{
    const xen_cpuid_leaf_t key = { leaf, subleaf };

    return bsearch(&key, leaves, nr_leaves, sizeof(*leaves), compare_leaves);
}

int xc_cpu_policy_apply_cpuid(xc_interface *xch, xc_cpu_policy_t policy,
                              const struct xc_xend_cpuid *cpuid, bool hvm)
{
    int rc;
    xc_cpu_policy_t host = NULL, def = NULL;

    host = xc_cpu_policy_init();
    def = xc_cpu_policy_init();
    if ( !host || !def )
    {
        PERROR("Failed to init policies");
        rc = -ENOMEM;
        goto out;
    }

    /* Get the domain type's default policy. */
    rc = xc_cpu_policy_get_system(xch, hvm ? XEN_SYSCTL_cpu_policy_hvm_default
                                           : XEN_SYSCTL_cpu_policy_pv_default,
                                  def);
    if ( rc )
    {
        PERROR("Failed to obtain %s def policy", hvm ? "hvm" : "pv");
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
        xen_cpuid_leaf_t def_leaf;
        xen_cpuid_leaf_t host_leaf;

        rc = xc_cpu_policy_get_cpuid(xch, policy, cpuid->leaf, cpuid->subleaf,
                                     &cur_leaf);
        if ( rc )
        {
            ERROR("Failed to get current policy leaf %#x subleaf %#x",
                  cpuid->leaf, cpuid->subleaf);
            goto out;
        }
        rc = xc_cpu_policy_get_cpuid(xch, def, cpuid->leaf, cpuid->subleaf,
                                     &def_leaf);
        if ( rc )
        {
            ERROR("Failed to get def policy leaf %#x subleaf %#x",
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
            const uint32_t *def_reg = &def_leaf.a + i;
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
                    val = test_bit(31 - j, def_reg);
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
    xc_cpu_policy_destroy(def);
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
    struct xc_cpu_policy policy = { };
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
     * Account for features which have been disabled by default since Xen 4.13,
     * so migrated-in VM's don't risk seeing features disappearing.
     */
    if ( restore )
    {
        policy.cpuid = *p;
        xc_cpu_policy_make_compatible(xch, &policy, di.hvm);
        *p = policy.cpuid;
    }

    if ( featureset )
    {
        policy.cpuid = *p;
        rc = xc_cpu_policy_apply_featureset(xch, &policy, featureset,
                                            nr_features);
        if ( rc )
        {
            ERROR("Failed to apply featureset to policy");
            goto out;
        }
        *p = policy.cpuid;
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

    policy.cpuid = *p;
    rc = xc_cpu_policy_legacy_topology(xch, &policy, di.hvm);
    if ( rc )
        goto out;
    *p = policy.cpuid;

    rc = xc_cpu_policy_apply_cpuid(xch, &policy, cpuid, di.hvm);
    if ( rc )
        goto out;

    rc = x86_cpuid_copy_to_buffer(p, leaves, &nr_leaves);
    if ( rc )
    {
        ERROR("Failed to serialise CPUID (%d = %s)", -rc, strerror(-rc));
        goto out;
    }

    rc = xc_set_domain_cpu_policy(xch, domid, nr_leaves, leaves, 0, NULL,
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
    return calloc(1, sizeof(struct xc_cpu_policy));
}

void xc_cpu_policy_destroy(xc_cpu_policy_t policy)
{
    if ( policy )
        free(policy);
}

static int deserialize_policy(xc_interface *xch, xc_cpu_policy_t policy,
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
                             xc_cpu_policy_t policy)
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
                             xc_cpu_policy_t policy)
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
                             const xc_cpu_policy_t policy)
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

int xc_cpu_policy_serialise(xc_interface *xch, const xc_cpu_policy_t p,
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

int xc_cpu_policy_get_cpuid(xc_interface *xch, const xc_cpu_policy_t policy,
                            uint32_t leaf, uint32_t subleaf,
                            xen_cpuid_leaf_t *out)
{
    unsigned int nr_leaves = ARRAY_SIZE(policy->leaves);
    xen_cpuid_leaf_t *tmp;
    int rc;

    rc = xc_cpu_policy_serialise(xch, policy, policy->leaves, &nr_leaves,
                                 NULL, 0);
    if ( rc )
        return rc;

    tmp = find_leaf(policy->leaves, nr_leaves, leaf, subleaf);
    if ( !tmp )
    {
        /* Unable to find a matching leaf. */
        errno = ENOENT;
        return -1;
    }

    *out = *tmp;
    return 0;
}

static int compare_entries(const void *l, const void *r)
{
    const xen_msr_entry_t *lhs = l;
    const xen_msr_entry_t *rhs = r;

    if ( lhs->idx == rhs->idx )
        return 0;
    return lhs->idx < rhs->idx ? -1 : 1;
}

static xen_msr_entry_t *find_entry(xen_msr_entry_t *entries,
                                   unsigned int nr_entries, unsigned int index)
{
    const xen_msr_entry_t key = { index };

    return bsearch(&key, entries, nr_entries, sizeof(*entries), compare_entries);
}

int xc_cpu_policy_get_msr(xc_interface *xch, const xc_cpu_policy_t policy,
                          uint32_t msr, xen_msr_entry_t *out)
{
    unsigned int nr_entries = ARRAY_SIZE(policy->entries);
    xen_msr_entry_t *tmp;
    int rc;

    rc = xc_cpu_policy_serialise(xch, policy, NULL, 0,
                                 policy->entries, &nr_entries);
    if ( rc )
        return rc;

    tmp = find_entry(policy->entries, nr_entries, msr);
    if ( !tmp )
    {
        /* Unable to find a matching MSR. */
        errno = ENOENT;
        return -1;
    }

    *out = *tmp;
    return 0;
}

int xc_cpu_policy_update_cpuid(xc_interface *xch, xc_cpu_policy_t policy,
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

int xc_cpu_policy_update_msrs(xc_interface *xch, xc_cpu_policy_t policy,
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

bool xc_cpu_policy_is_compatible(xc_interface *xch, const xc_cpu_policy_t host,
                                 const xc_cpu_policy_t guest)
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

static bool level_msr(unsigned int index, uint64_t val1, uint64_t val2,
                      uint64_t *out)
{
    *out = 0;

    switch ( index )
    {
    case MSR_INTEL_PLATFORM_INFO:
        *out = val1 & val2;
        return true;

    case MSR_ARCH_CAPABILITIES:
        *out = val1 & val2;
        /*
         * Set RSBA if present on any of the input values to notice the guest
         * might run on vulnerable hardware at some point.
         */
        *out |= (val1 | val2) & ARCH_CAPS_RSBA;
        return true;
    }

    return false;
}

/* Only level featuresets so far. */
static bool level_leaf(const xen_cpuid_leaf_t *l1, const xen_cpuid_leaf_t *l2,
                       xen_cpuid_leaf_t *out)
{
    *out = (xen_cpuid_leaf_t){ };

    switch ( l1->leaf )
    {
    case 0x1:
    case 0x80000001:
        out->c = l1->c & l2->c;
        out->d = l1->d & l2->d;
        return true;

    case 0xd:
        if ( l1->subleaf != 1 )
            break;
        /*
         * Only take Da1 into account, the rest of subleaves will be dropped
         * and recalculated by recalculate_xstate.
         */
        out->a = l1->a & l2->a;
        return true;

    case 0x7:
        if ( l1->subleaf )
            /* subleaf 0 EAX contains the max subleaf count. */
            out->a = l1->a & l2->a;
        out->b = l1->b & l2->b;
        out->c = l1->c & l2->c;
        out->d = l1->d & l2->d;
        return true;

    case 0x80000007:
        out->d = l1->d & l2->d;
        return true;

    case 0x80000008:
        out->b = l1->b & l2->b;
        return true;
    }

    return false;
}

int xc_cpu_policy_calc_compatible(xc_interface *xch,
                                  const xc_cpu_policy_t p1,
                                  const xc_cpu_policy_t p2,
                                  xc_cpu_policy_t out)
{
    unsigned int nr_leaves, nr_msrs, i, index;
    unsigned int p1_nr_leaves, p2_nr_leaves;
    unsigned int p1_nr_entries, p2_nr_entries;
    int rc;

    p1_nr_leaves = p2_nr_leaves = ARRAY_SIZE(p1->leaves);
    p1_nr_entries = p2_nr_entries = ARRAY_SIZE(p1->entries);

    rc = xc_cpu_policy_serialise(xch, p1, p1->leaves, &p1_nr_leaves,
                                 p1->entries, &p1_nr_entries);
    if ( rc )
        return rc;
    rc = xc_cpu_policy_serialise(xch, p2, p2->leaves, &p2_nr_leaves,
                                 p2->entries, &p2_nr_entries);
    if ( rc )
        return rc;

    index = 0;
    for ( i = 0; i < p1_nr_leaves; i++ )
    {
        xen_cpuid_leaf_t *l1 = &p1->leaves[i];
        xen_cpuid_leaf_t *l2 = find_leaf(p2->leaves, p2_nr_leaves,
                                         l1->leaf, l1->subleaf);

        if ( l2 && level_leaf(&out->leaves[index], l1, l2) )
        {
            out->leaves[index].leaf = l1->leaf;
            out->leaves[index].subleaf = l1->subleaf;
            index++;
        }
    }
    nr_leaves = index;

    index = 0;
    for ( i = 0; i < p1_nr_entries; i++ )
    {
        xen_msr_entry_t *l1 = &p1->entries[i];
        xen_msr_entry_t *l2 = find_entry(p2->entries, p2_nr_entries, l1->idx);

        if ( l2 &&
             level_msr(l1->idx, l1->val, l2->val, &out->entries[index].val) )
            out->entries[index++].idx = l1->idx;
    }
    nr_msrs = index;

    rc = deserialize_policy(xch, out, nr_leaves, nr_msrs);
    if ( rc )
    {
        errno = -rc;
        rc = -1;
    }

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

    /*
     * Account for features which have been disabled by default since Xen 4.13,
     * so migrated-in VM's don't risk seeing features disappearing.
     */
    policy->cpuid.basic.rdrand = host->cpuid.basic.rdrand;

    if ( hvm )
        policy->cpuid.feat.mpx = host->cpuid.feat.mpx;

 out:
    xc_cpu_policy_destroy(host);
    return rc;
}

int xc_cpu_policy_legacy_topology(xc_interface *xch, xc_cpu_policy_t policy,
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
        if ( !(policy->cpuid.basic.lppp & 0x80) )
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
             * UPDATE: I addition to avoiding overflow, some
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

    return 0;
}

int xc_cpu_policy_apply_featureset(xc_interface *xch, xc_cpu_policy_t policy,
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
