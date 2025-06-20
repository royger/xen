/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef GENERIC_PDX_H
#define GENERIC_PDX_H

#ifndef CONFIG_PDX_NONE

#define pdx_to_pfn pdx_to_pfn_xlate
#define pfn_to_pdx pfn_to_pdx_xlate
#define maddr_to_directmapoff maddr_to_directmapoff_xlate
#define directmapoff_to_maddr directmapoff_to_maddr_xlate

#endif /* !CONFIG_PDX_NONE */

#endif /* GENERIC_PDX_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
