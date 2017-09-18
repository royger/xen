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
#include <xen/softirq.h>
#include <xen/vpci.h>

#include <asm/msi.h>

static uint32_t vpci_msi_control_read(const struct pci_dev *pdev,
                                      unsigned int reg, void *data)
{
    const struct vpci_msi *msi = data;
    uint16_t val;

    /* Set the number of supported/configured messages. */
    val = MASK_INSR(fls(msi->max_vectors) - 1, PCI_MSI_FLAGS_QMASK);
    val |= MASK_INSR(fls(msi->vectors) - 1, PCI_MSI_FLAGS_QSIZE);

    val |= msi->enabled ? PCI_MSI_FLAGS_ENABLE : 0;
    val |= msi->masking ? PCI_MSI_FLAGS_MASKBIT : 0;
    val |= msi->address64 ? PCI_MSI_FLAGS_64BIT : 0;

    return val;
}

static void vpci_msi_enable(const struct pci_dev *pdev, struct vpci_msi *msi,
                            unsigned int vectors)
{
    int ret;

    ASSERT(!msi->enabled);
    ret = vpci_msi_arch_enable(msi, pdev, vectors);
    if ( ret )
        return;

    /* Apply the mask bits. */
    if ( msi->masking )
    {
        unsigned int i;
        uint32_t mask = msi->mask;

        for ( i = ffs(mask) - 1; mask && i < vectors; i = ffs(mask) - 1 )
        {
            vpci_msi_arch_mask(msi, pdev, i, true);
            __clear_bit(i, &mask);
        }
    }

    __msi_set_enable(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                     PCI_FUNC(pdev->devfn), msi->pos, 1);

    msi->enabled = true;
}

static int vpci_msi_disable(const struct pci_dev *pdev, struct vpci_msi *msi)
{
    int ret;

    ASSERT(msi->enabled);
    __msi_set_enable(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                     PCI_FUNC(pdev->devfn), msi->pos, 0);

    ret = vpci_msi_arch_disable(msi, pdev);
    if ( !ret )
        msi->enabled = false;

    return ret;
}

static void vpci_msi_control_write(const struct pci_dev *pdev,
                                   unsigned int reg, uint32_t val, void *data)
{
    struct vpci_msi *msi = data;
    unsigned int vectors = 1 << MASK_EXTR(val, PCI_MSI_FLAGS_QSIZE);
    bool new_enabled = val & PCI_MSI_FLAGS_ENABLE;

    if ( vectors > msi->max_vectors )
        vectors = msi->max_vectors;

    /*
     * No change if the enable field and the number of vectors is
     * the same or the device is not enabled, in which case the
     * vectors field can be updated directly.
     */
    if ( new_enabled == msi->enabled &&
         (vectors == msi->vectors || !msi->enabled) )
    {
        msi->vectors = vectors;
        return;
    }

    if ( new_enabled )
    {
        /*
         * If the device is already enabled it means the number of
         * enabled messages has changed. Disable and re-enable the
         * device in order to apply the change.
         */
        if ( msi->enabled && vpci_msi_disable(pdev, msi) )
            /*
             * Somehow Xen has not been able to disable the
             * configured MSI messages, leave the device state as-is,
             * so that the guest can try to disable MSI again.
             */
            return;

        vpci_msi_enable(pdev, msi, vectors);
    }
    else
        vpci_msi_disable(pdev, msi);

    msi->vectors = vectors;
}

/* Handlers for the address field (32bit or low part of a 64bit address). */
static uint32_t vpci_msi_address_read(const struct pci_dev *pdev,
                                      unsigned int reg, void *data)
{
    const struct vpci_msi *msi = data;

    return msi->address;
}

static void vpci_msi_address_write(const struct pci_dev *pdev,
                                   unsigned int reg, uint32_t val, void *data)
{
    struct vpci_msi *msi = data;

    /* Clear low part. */
    msi->address &= ~0xffffffffull;
    msi->address |= val;
}

/* Handlers for the high part of a 64bit address field. */
static uint32_t vpci_msi_address_upper_read(const struct pci_dev *pdev,
                                            unsigned int reg, void *data)
{
    const struct vpci_msi *msi = data;

    return msi->address >> 32;
}

static void vpci_msi_address_upper_write(const struct pci_dev *pdev,
                                         unsigned int reg, uint32_t val,
                                         void *data)
{
    struct vpci_msi *msi = data;

    /* Clear high part. */
    msi->address &= 0xffffffff;
    msi->address |= (uint64_t)val << 32;
}

/* Handlers for the data field. */
static uint32_t vpci_msi_data_read(const struct pci_dev *pdev,
                                   unsigned int reg, void *data)
{
    const struct vpci_msi *msi = data;

    return msi->data;
}

static void vpci_msi_data_write(const struct pci_dev *pdev, unsigned int reg,
                                uint32_t val, void *data)
{
    struct vpci_msi *msi = data;

    msi->data = val;
}

/* Handlers for the MSI mask bits. */
static uint32_t vpci_msi_mask_read(const struct pci_dev *pdev,
                                   unsigned int reg, void *data)
{
    const struct vpci_msi *msi = data;

    return msi->mask;
}

static void vpci_msi_mask_write(const struct pci_dev *pdev, unsigned int reg,
                                uint32_t val, void *data)
{
    struct vpci_msi *msi = data;
    uint32_t dmask;

    dmask = msi->mask ^ val;

    if ( !dmask )
        return;

    if ( msi->enabled )
    {
        unsigned int i;

        for ( i = ffs(dmask) - 1; dmask && i < msi->vectors;
              i = ffs(dmask) - 1 )
        {
            vpci_msi_arch_mask(msi, pdev, i, (val >> i) & 1);
            __clear_bit(i, &dmask);
        }
    }

    msi->mask = val;
}

static int vpci_init_msi(struct pci_dev *pdev)
{
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    struct vpci_msi *msi;
    unsigned int pos;
    uint16_t control;
    int ret;

    pos = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSI);
    if ( !pos )
        return 0;

    msi = xzalloc(struct vpci_msi);
    if ( !msi )
        return -ENOMEM;

    msi->pos = pos;

    ret = vpci_add_register(pdev, vpci_msi_control_read,
                            vpci_msi_control_write,
                            msi_control_reg(pos), 2, msi);
    if ( ret )
    {
        xfree(msi);
        return ret;
    }

    /* Get the maximum number of vectors the device supports. */
    control = pci_conf_read16(seg, bus, slot, func, msi_control_reg(pos));
    msi->max_vectors = multi_msi_capable(control);
    ASSERT(msi->max_vectors <= 32);

    /* The multiple message enable is 0 after reset (1 message enabled). */
    msi->vectors = 1;

    /* No PIRQ bound yet. */
    vpci_msi_arch_init(msi);

    msi->address64 = is_64bit_address(control);
    msi->masking = is_mask_bit_support(control);

    ret = vpci_add_register(pdev, vpci_msi_address_read,
                            vpci_msi_address_write,
                            msi_lower_address_reg(pos), 4, msi);
    if ( ret )
    {
        xfree(msi);
        return ret;
    }

    ret = vpci_add_register(pdev, vpci_msi_data_read, vpci_msi_data_write,
                            msi_data_reg(pos, msi->address64), 2,
                            msi);
    if ( ret )
    {
        xfree(msi);
        return ret;
    }

    if ( msi->address64 )
    {
        ret = vpci_add_register(pdev, vpci_msi_address_upper_read,
                                vpci_msi_address_upper_write,
                                msi_upper_address_reg(pos), 4, msi);
        if ( ret )
        {
            xfree(msi);
            return ret;
        }
    }

    if ( msi->masking )
    {
        ret = vpci_add_register(pdev, vpci_msi_mask_read, vpci_msi_mask_write,
                                msi_mask_bits_reg(pos, msi->address64), 4,
                                msi);
        if ( ret )
        {
            xfree(msi);
            return ret;
        }
    }

    pdev->vpci->msi = msi;

    return 0;
}
REGISTER_VPCI_INIT(vpci_init_msi, VPCI_PRIORITY_LOW);

void vpci_dump_msi(void)
{
    struct domain *d;

    for_each_domain ( d )
    {
        const struct pci_dev *pdev;

        if ( !has_vpci(d) )
            continue;

        printk("vPCI MSI/MSI-X information for d%d\n", d->domain_id);

        list_for_each_entry ( pdev, &d->arch.pdev_list, domain_list )
        {
            uint8_t seg = pdev->seg, bus = pdev->bus;
            uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
            const struct vpci_msi *msi = pdev->vpci->msi;
            const struct vpci_msix *msix = pdev->vpci->msix;

            if ( msi || msix )
                printk("Device %04x:%02x:%02x.%u\n", seg, bus, slot, func);

            if ( !spin_trylock(&pdev->vpci->lock) )
            {
                printk("Unable to get vPCI lock, skipping\n");
                continue;
            }

            if ( msi )
            {
                printk(" MSI\n");

                printk("  Enabled: %u Supports masking: %u 64-bit addresses: %u\n",
                       msi->enabled, msi->masking, msi->address64);
                printk("  Max vectors: %u enabled vectors: %u\n",
                       msi->max_vectors, msi->vectors);

                vpci_msi_arch_print(msi);

                if ( msi->masking )
                    printk("  mask=%08x\n", msi->mask);
            }

            if ( msix )
            {
                unsigned int i;

                printk(" MSI-X\n");

                printk("  Max entries: %u maskall: %u enabled: %u\n",
                       msix->max_entries, msix->masked, msix->enabled);

                printk("  Table entries:\n");
                for ( i = 0; i < msix->max_entries; i++ )
                    vpci_msix_arch_print_entry(&msix->entries[i]);
            }

            spin_unlock(&pdev->vpci->lock);
            process_pending_softirqs();
        }
    }
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
