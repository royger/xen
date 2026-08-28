/*
 * Handlers for accesses to DesignWare Vendor Specific capabilities
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include "private.h"

#include <xen/io.h>
#include <xen/lib.h>
#include <xen/sched.h>

#include <asm/msi.h>
#include <asm/p2m.h>
#include <asm/x86_emulate.h>

#define XILINX_VENDOR_ID        0x10ee
#define SYNOPSYS_VENDOR_ID      0x16c3

#define DW_PCIE_VSEC_DMA_ID     0x6

static int cf_check cleanup_designware_dma(const struct pci_dev *pdev,
                                           bool hide)
{
    /* TODO */
    return 0;
}

static int cf_check init_designware_dma(struct pci_dev *pdev)
{
    uint16_t vendor = pci_conf_read16(pdev->sbdf, PCI_VENDOR_ID);
    unsigned int pos = 0;

    pos = pci_find_vsec_capability(pdev, vendor, DW_PCIE_VSEC_DMA_ID);

    if ( !pos )
    {
        printk("%pp: DesignWare eDMA capability not found\n", &pdev->sbdf);
        return -ENODEV;
    }

    printk("%pp: DesignWare eDMA capability found at offset %#x\n",
           &pdev->sbdf, pos);

    return 0;
}
REGISTER_VPCI_EXTCAP_VNDR(DW_PCIE_VSEC_DMA_ID, XILINX_VENDOR_ID,
                          init_designware_dma, cleanup_designware_dma);
REGISTER_VPCI_EXTCAP_VNDR(DW_PCIE_VSEC_DMA_ID, SYNOPSYS_VENDOR_ID,
                          init_designware_dma, cleanup_designware_dma);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
