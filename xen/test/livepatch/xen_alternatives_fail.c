/*
 * Copyright (c) 2024 Cloud Software Group.
 *
 */

#include "config.h"
#include <xen/lib.h>
#include <xen/livepatch_payload.h>

#include <asm/alternative.h>
#include <asm/cpuid.h>

void test_alternatives(void)
{
    alternative("", "", NCAPINTS * 32);
}

/* Set a hook so the loading logic in Xen don't consider the payload empty. */
LIVEPATCH_LOAD_HOOK(test_alternatives);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
