#ifndef _ASM_X86_TEST_H_
#define _ASM_X86_TEST_H_

#include <xen/types.h>

int test_smoc(uint32_t selection, uint32_t *results);

static inline void execute_selftests(void)
{
    const uint32_t exec_mask = XEN_SYSCTL_TEST_SMOC_ALL;
    uint32_t result;
    int rc;

    printk(XENLOG_INFO "Checking Self Modify Code\n");
    rc = test_smoc(exec_mask, &result);
    if ( rc || (result & exec_mask) != exec_mask )
        add_taint(TAINT_ERROR_SELFTEST);
}

#endif	/* _ASM_X86_TEST_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
