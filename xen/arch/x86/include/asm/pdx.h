/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef X86_PDX_H
#define X86_PDX_H

#ifndef CONFIG_PDX_NONE

#include <asm/alternative.h>

/*
 * Introduce a macro to avoid repeating the same asm goto block in each helper.
 * Note the macro is strictly tied to the code in the helpers.
 */
#define PDX_ASM_GOTO_SKIP                           \
    asm_inline goto (                               \
        ALTERNATIVE(                                \
            "",                                     \
            "jmp %l[skip]",                         \
            ALT_NOT(X86_FEATURE_PDX_COMPRESSION))   \
        : : : : skip )

static inline unsigned long pfn_to_pdx(unsigned long pfn)
{
    PDX_ASM_GOTO_SKIP;

    return pfn_to_pdx_xlate(pfn);

 skip:
    return pfn;
}

static inline unsigned long pdx_to_pfn(unsigned long pdx)
{
    PDX_ASM_GOTO_SKIP;

    return pdx_to_pfn_xlate(pdx);

 skip:
    return pdx;
}

static inline unsigned long maddr_to_directmapoff(paddr_t ma)
{
    PDX_ASM_GOTO_SKIP;

    return maddr_to_directmapoff_xlate(ma);

 skip:
    return ma;
}

static inline paddr_t directmapoff_to_maddr(unsigned long offset)
{
    PDX_ASM_GOTO_SKIP;

    return directmapoff_to_maddr_xlate(offset);

 skip:
    return offset;
}

#undef PDX_SKIP_ASM_GOTO

#endif /* !CONFIG_PDX_NONE */

#endif /* X86_PDX_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
