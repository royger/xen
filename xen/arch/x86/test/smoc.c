/* SPDX-License-Identifier: GPL-2.0 */

#include <xen/errno.h>

#include <asm/alternative.h>
#include <asm/cpufeature.h>
#include <asm/test.h>

static bool cf_check test_insn_replacement(void)
{
#define EXPECTED_VALUE 2
    unsigned int r = ~EXPECTED_VALUE;

    alternative_io("", "mov %1, %0", X86_FEATURE_ALWAYS,
                   "+r" (r), "i" (EXPECTED_VALUE));

    return r == EXPECTED_VALUE;
#undef EXPECTED_VALUE
}

int test_smoc(uint32_t selection, uint32_t *results)
{
    struct {
        unsigned int mask;
        bool (*test)(void);
        const char *name;
    } static const tests[] = {
        { XEN_SYSCTL_TEST_SMOC_INSN_REPL, &test_insn_replacement,
          "alternative instruction replacement" },
#ifdef CONFIG_LIVEPATCH
        { XEN_SYSCTL_TEST_SMOC_LP_INSN, &test_lp_insn_replacement,
          "livepatch instruction replacement" },
#endif
    };
    unsigned int i;

    if ( selection & ~XEN_SYSCTL_TEST_SMOC_ALL )
        return -EINVAL;

    if ( results )
        *results = 0;

    for ( i = 0; i < ARRAY_SIZE(tests); i++ )
    {
        if ( !(selection & tests[i].mask) )
            continue;

        if ( tests[i].test() )
        {
            if ( results )
                *results |= tests[i].mask;
            continue;
        }

        if ( system_state < SYS_STATE_active )
            printk(XENLOG_ERR "%s test failed\n", tests[i].name);
    }

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
