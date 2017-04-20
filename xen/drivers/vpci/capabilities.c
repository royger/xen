/*
 * Generic functionality for handling accesses to the PCI capabilities from
 * the configuration space.
 *
 * Copyright (C) 2017 Citrix Systems R&D
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

#include <xen/sched.h>
#include <xen/vpci.h>

struct vpci_capability {
    struct list_head next;
    uint8_t offset;
    bool masked;
};

static int vpci_cap_read(struct pci_dev *pdev, unsigned int reg,
                         union vpci_val *val, void *data)
{
    struct vpci_capability *cap = data;

    val->half_word = 0;

    /* Return the position of the next non-masked capability. */
    list_for_each_entry_continue ( cap, &pdev->vpci->cap_list, next )
    {
        if ( !cap->masked )
        {
            val->half_word = cap->offset;
            break;
        }
    }

    return 0;
}

static int vpci_cap_write(struct pci_dev *pdev, unsigned int reg,
                          union vpci_val val, void *data)
{
    /* Ignored. */
    return 0;
}

static int vpci_index_capabilities(struct pci_dev *pdev)
{
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    uint8_t pos = PCI_CAPABILITY_LIST;
    uint16_t status;
    unsigned int max_cap = 48;
    struct vpci_capability *cap;
    int rc;

    INIT_LIST_HEAD(&pdev->vpci->cap_list);

    /* Check if device has capabilities. */
    status = pci_conf_read16(seg, bus, slot, func, PCI_STATUS);
    if ( !(status & PCI_STATUS_CAP_LIST) )
        return 0;

    /* Add the root capability pointer. */
    cap = xzalloc(struct vpci_capability);
    if ( !cap )
        return -ENOMEM;

    cap->offset = pos;
    list_add_tail(&cap->next, &pdev->vpci->cap_list);
    rc = xen_vpci_add_register(pdev, vpci_cap_read, vpci_cap_write, pos,
                               1, cap);
    if ( rc )
        return rc;

    /*
     * Iterate over the list of capabilities present in the device, and
     * add a handler for each register pointer to the next item
     * (PCI_CAP_LIST_NEXT).
     */
    while ( max_cap-- )
    {
        pos = pci_conf_read8(seg, bus, slot, func, pos);
        if ( pos < 0x40 )
            break;

        cap = xzalloc(struct vpci_capability);
        if ( !cap )
            return -ENOMEM;

        cap->offset = pos;
        list_add_tail(&cap->next, &pdev->vpci->cap_list);
        pos += PCI_CAP_LIST_NEXT;
        rc = xen_vpci_add_register(pdev, vpci_cap_read, vpci_cap_write, pos,
                                   1, cap);
        if ( rc )
            return rc;
    }

    return 0;
}

void xen_vpci_mask_capability(struct pci_dev *pdev, uint8_t cap_id)
{
    struct vpci_capability *cap;
    uint8_t cap_offset;

    cap_offset = pci_find_cap_offset(pdev->seg, pdev->bus,
                                     PCI_SLOT(pdev->devfn),
                                     PCI_FUNC(pdev->devfn), cap_id);
    if ( !cap_offset )
        return;

    list_for_each_entry ( cap, &pdev->vpci->cap_list, next )
    {
        if ( cap->offset == cap_offset )
        {
            cap->masked = true;
            break;
        }
    }
}

REGISTER_VPCI_INIT(vpci_index_capabilities, true);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

