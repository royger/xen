/*
 * Handlers for accesses to the MSI capability structure.
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
#include <asm/msi.h>
#include <xen/keyhandler.h>

/* Handlers for the MSI control field (PCI_MSI_FLAGS). */
static int vpci_msi_control_read(struct pci_dev *pdev, unsigned int reg,
                                 union vpci_val *val, void *data)
{
    struct vpci_msi *msi = data;

    if ( msi->enabled )
        val->word |= PCI_MSI_FLAGS_ENABLE;
    if ( msi->masking )
        val->word |= PCI_MSI_FLAGS_MASKBIT;
    if ( msi->address64 )
        val->word |= PCI_MSI_FLAGS_64BIT;

    /* Set multiple message capable. */
    val->word |= ((fls(msi->max_vectors) - 1) << 1) & PCI_MSI_FLAGS_QMASK;

    /* Set current number of configured vectors. */
    val->word |= ((fls(msi->guest_vectors) - 1) << 4) & PCI_MSI_FLAGS_QSIZE;

    return 0;
}

static int vpci_msi_control_write(struct pci_dev *pdev, unsigned int reg,
                                  union vpci_val val, void *data)
{
    struct vpci_msi *msi = data;
    unsigned int vectors = 1 << ((val.word & PCI_MSI_FLAGS_QSIZE) >> 4);
    int rc;

    if ( vectors > msi->max_vectors )
        return -EINVAL;

    msi->guest_vectors = vectors;

    if ( !!(val.word & PCI_MSI_FLAGS_ENABLE) == msi->enabled )
        return 0;

    if ( val.word & PCI_MSI_FLAGS_ENABLE )
    {
        ASSERT(!msi->enabled && !msi->vectors);

        rc = vpci_msi_enable(&msi->arch, pdev, msi->address, msi->data,
                             vectors);
        if ( rc )
            return rc;

        /* Apply the mask bits. */
        if ( msi->masking )
        {
            uint32_t mask = msi->mask;

            while ( mask )
            {
                unsigned int i = ffs(mask);

                vpci_msi_mask(&msi->arch, i, true);
                __clear_bit(i, &mask);
            }
        }

        __msi_set_enable(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                         PCI_FUNC(pdev->devfn), reg - PCI_MSI_FLAGS, 1);

        msi->vectors = vectors;
        msi->enabled = true;
    }
    else
    {
        ASSERT(msi->enabled && msi->vectors);

        __msi_set_enable(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                         PCI_FUNC(pdev->devfn), reg - PCI_MSI_FLAGS, 0);


        rc = vpci_msi_disable(&msi->arch, pdev, msi->vectors);
        if ( rc )
            return rc;

        msi->vectors = 0;
        msi->enabled = false;
    }

    return rc;
}

/* Handlers for the address field (32bit or low part of a 64bit address). */
static int vpci_msi_address_read(struct pci_dev *pdev, unsigned int reg,
                                 union vpci_val *val, void *data)
{
    struct vpci_msi *msi = data;

    val->double_word = msi->address;

    return 0;
}

static int vpci_msi_address_write(struct pci_dev *pdev, unsigned int reg,
                                  union vpci_val val, void *data)
{
    struct vpci_msi *msi = data;

    /* Clear low part. */
    msi->address &= ~GENMASK(31, 0);
    msi->address |= val.double_word;

    return 0;
}

/* Handlers for the high part of a 64bit address field. */
static int vpci_msi_address_upper_read(struct pci_dev *pdev, unsigned int reg,
                                       union vpci_val *val, void *data)
{
    struct vpci_msi *msi = data;

    val->double_word = msi->address >> 32;

    return 0;
}

static int vpci_msi_address_upper_write(struct pci_dev *pdev, unsigned int reg,
                                        union vpci_val val, void *data)
{
    struct vpci_msi *msi = data;

    /* Clear high part. */
    msi->address &= ~GENMASK(63, 32);
    msi->address |= (uint64_t)val.double_word << 32;

    return 0;
}

/* Handlers for the data field. */
static int vpci_msi_data_read(struct pci_dev *pdev, unsigned int reg,
                              union vpci_val *val, void *data)
{
    struct vpci_msi *msi = data;

    val->word = msi->data;

    return 0;
}

static int vpci_msi_data_write(struct pci_dev *pdev, unsigned int reg,
                               union vpci_val val, void *data)
{
    struct vpci_msi *msi = data;

    msi->data = val.word;

    return 0;
}

static int vpci_msi_mask_read(struct pci_dev *pdev, unsigned int reg,
                              union vpci_val *val, void *data)
{
    struct vpci_msi *msi = data;

    val->double_word = msi->mask;

    return 0;
}

static int vpci_msi_mask_write(struct pci_dev *pdev, unsigned int reg,
                               union vpci_val val, void *data)
{
    struct vpci_msi *msi = data;
    uint32_t dmask;

    dmask = msi->mask ^ val.double_word;

    if ( !dmask )
        return 0;

    while ( dmask && msi->enabled )
    {
        unsigned int i = ffs(dmask);

        vpci_msi_mask(&msi->arch, i, !test_bit(i, &msi->mask));
        __clear_bit(i, &dmask);
    }

    msi->mask = val.double_word;
    return 0;
}

static int vpci_init_msi(struct pci_dev *pdev)
{
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    struct vpci_msi *msi = NULL;
    unsigned int msi_offset;
    uint16_t control;
    int rc;

    msi_offset = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSI);
    if ( !msi_offset )
        return 0;

    if ( !vpci_msi_enabled(pdev->domain) )
    {
        xen_vpci_mask_capability(pdev, PCI_CAP_ID_MSI);
        return 0;
    }

    msi = xzalloc(struct vpci_msi);
    if ( !msi )
        return -ENOMEM;

    control = pci_conf_read16(seg, bus, slot, func,
                              msi_control_reg(msi_offset));

    rc = xen_vpci_add_register(pdev, vpci_msi_control_read,
                               vpci_msi_control_write,
                               msi_control_reg(msi_offset), 2, msi);
    if ( rc )
    {
        dprintk(XENLOG_ERR,
                "%04x:%02x:%02x.%u: failed to add handler for MSI control: %d\n",
                seg, bus, slot, func, rc);
        goto error;
    }

    /* Get the maximum number of vectors the device supports. */
    msi->max_vectors = multi_msi_capable(control);
    ASSERT(msi->max_vectors <= 32);

    /* Initial value after reset. */
    msi->guest_vectors = 1;

    /* No PIRQ bind yet. */
    vpci_msi_arch_init(&msi->arch);

    if ( is_64bit_address(control) )
        msi->address64 = true;
    if ( is_mask_bit_support(control) )
        msi->masking = true;

    rc = xen_vpci_add_register(pdev, vpci_msi_address_read,
                               vpci_msi_address_write,
                               msi_lower_address_reg(msi_offset), 4, msi);
    if ( rc )
    {
        dprintk(XENLOG_ERR,
                "%04x:%02x:%02x.%u: failed to add handler for MSI address: %d\n",
                seg, bus, slot, func, rc);
        goto error;
    }

    rc = xen_vpci_add_register(pdev, vpci_msi_data_read, vpci_msi_data_write,
                               msi_data_reg(msi_offset, msi->address64), 2,
                               msi);
    if ( rc )
    {
        dprintk(XENLOG_ERR,
                "%04x:%02x:%02x.%u: failed to add handler for MSI address: %d\n",
                seg, bus, slot, func, rc);
        goto error;
    }

    if ( msi->address64 )
    {
        rc = xen_vpci_add_register(pdev, vpci_msi_address_upper_read,
                                   vpci_msi_address_upper_write,
                                   msi_upper_address_reg(msi_offset), 4, msi);
        if ( rc )
        {
            dprintk(XENLOG_ERR,
                    "%04x:%02x:%02x.%u: failed to add handler for MSI address: %d\n",
                    seg, bus, slot, func, rc);
            goto error;
        }
    }

    if ( msi->masking )
    {
        rc = xen_vpci_add_register(pdev, vpci_msi_mask_read,
                                   vpci_msi_mask_write,
                                   msi_mask_bits_reg(msi_offset,
                                                     msi->address64), 4, msi);
        if ( rc )
        {
            dprintk(XENLOG_ERR,
                    "%04x:%02x:%02x.%u: failed to add handler for MSI mask: %d\n",
                    seg, bus, slot, func, rc);
            goto error;
        }
    }

    pdev->vpci->msi = msi;

    return 0;

 error:
    ASSERT(rc);
    xfree(msi);
    return rc;
}

REGISTER_VPCI_INIT(vpci_init_msi, false);

static void vpci_dump_msi(unsigned char key)
{
    struct domain *d;
    struct pci_dev *pdev;

    printk("Guest MSI information:\n");

    for_each_domain ( d )
    {
        if ( !has_vpci(d) )
            continue;

        vpci_lock(d);
        list_for_each_entry ( pdev, &d->arch.pdev_list, domain_list)
        {
            uint8_t seg = pdev->seg, bus = pdev->bus;
            uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
            struct vpci_msi *msi = pdev->vpci->msi;
            uint16_t data;
            uint64_t addr;

            if ( !msi )
                continue;

            printk("Device %04x:%02x:%02x.%u\n", seg, bus, slot, func);

            printk("Enabled: %u Supports masking: %u 64-bit addresses: %u\n",
                   msi->enabled, msi->masking, msi->address64);
            printk("Max vectors: %u guest vectors: %u enabled vectors: %u\n",
                   msi->max_vectors, msi->guest_vectors, msi->vectors);

            vpci_msi_arch_print(&msi->arch);

            data = msi->data;
            addr = msi->address;
            printk("vec=%#02x%7s%6s%3sassert%5s%7s dest_id=%lu\n",
                   (data & MSI_DATA_VECTOR_MASK) >> MSI_DATA_VECTOR_SHIFT,
                   data & MSI_DATA_DELIVERY_LOWPRI ? "lowest" : "fixed",
                   data & MSI_DATA_TRIGGER_LEVEL ? "level" : "edge",
                   data & MSI_DATA_LEVEL_ASSERT ? "" : "de",
                   addr & MSI_ADDR_DESTMODE_LOGIC ? "log" : "phys",
                   addr & MSI_ADDR_REDIRECTION_LOWPRI ? "lowest" : "cpu",
                   (addr & MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT);

            if ( msi->masking )
                printk("mask=%#032x\n", msi->mask);
            printk("\n");
        }
        vpci_unlock(d);
    }
}

static int __init vpci_msi_setup_keyhandler(void)
{
    register_keyhandler('Z', vpci_dump_msi, "dump guest MSI state", 1);
    return 0;
}
__initcall(vpci_msi_setup_keyhandler);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

