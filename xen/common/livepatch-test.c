/* SPDX-License-Identifier: GPL-2.0 */

/* Dummy file for testing livepatch functionality. */
#include <xen/livepatch.h>

int livepatch_test(struct xen_sysctl_livepatch_test *test)
{
    test->result = 1;
    return 0;
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
