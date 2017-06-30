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
static void vpci_msi_control_read(struct pci_dev *pdev, unsigned int reg,
                                  union vpci_val *val, void *data)
{
    const struct vpci_msi *msi = data;

    /* Set multiple message capable. */
    val->u16 = MASK_INSR(fls(msi->max_vectors) - 1, PCI_MSI_FLAGS_QMASK);

    if ( msi->enabled ) {
        val->u16 |= PCI_MSI_FLAGS_ENABLE;
        val->u16 |= MASK_INSR(fls(msi->vectors) - 1, PCI_MSI_FLAGS_QSIZE);
    }
    val->u16 |= msi->masking ? PCI_MSI_FLAGS_MASKBIT : 0;
    val->u16 |= msi->address64 ? PCI_MSI_FLAGS_64BIT : 0;
}

static void vpci_msi_enable(struct pci_dev *pdev, struct vpci_msi *msi,
                            unsigned int vectors)
{
    int ret;

    ASSERT(!msi->vectors);

    ret = vpci_msi_arch_enable(&msi->arch, pdev, msi->address, msi->data,
                               vectors);
    if ( ret )
        return;

    /* Apply the mask bits. */
    if ( msi->masking )
    {
        unsigned int i;
        uint32_t mask = msi->mask;

        for ( i = ffs(mask) - 1; mask && i < vectors; i = ffs(mask) - 1 )
        {
            vpci_msi_arch_mask(&msi->arch, pdev, i, true);
            __clear_bit(i, &mask);
        }
    }

    __msi_set_enable(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                     PCI_FUNC(pdev->devfn), msi->pos, 1);

    msi->vectors = vectors;
    msi->enabled = true;
}

static int vpci_msi_disable(struct pci_dev *pdev, struct vpci_msi *msi)
{
    int ret;

    ASSERT(msi->vectors);

    __msi_set_enable(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                     PCI_FUNC(pdev->devfn), msi->pos, 0);

    ret = vpci_msi_arch_disable(&msi->arch, pdev, msi->vectors);
    if ( ret )
        return ret;

    msi->vectors = 0;
    msi->enabled = false;

    return 0;
}

static void vpci_msi_control_write(struct pci_dev *pdev, unsigned int reg,
                                   union vpci_val val, void *data)
{
    struct vpci_msi *msi = data;
    unsigned int vectors = 1 << MASK_EXTR(val.u16, PCI_MSI_FLAGS_QSIZE);
    int ret;

    if ( vectors > msi->max_vectors )
        vectors = msi->max_vectors;

    if ( !!(val.u16 & PCI_MSI_FLAGS_ENABLE) == msi->enabled &&
         (vectors == msi->vectors || !msi->enabled) )
        return;

    if ( val.u16 & PCI_MSI_FLAGS_ENABLE )
    {
        if ( msi->enabled )
        {
            /*
             * Change to the number of enabled vectors, disable and
             * enable MSI in order to apply it.
             */
            ret = vpci_msi_disable(pdev, msi);
            if ( ret )
                return;
        }
        vpci_msi_enable(pdev, msi, vectors);
    }
    else
        vpci_msi_disable(pdev, msi);
}

/* Handlers for the address field (32bit or low part of a 64bit address). */
static void vpci_msi_address_read(struct pci_dev *pdev, unsigned int reg,
                                  union vpci_val *val, void *data)
{
    const struct vpci_msi *msi = data;

    val->u32 = msi->address;
}

static void vpci_msi_address_write(struct pci_dev *pdev, unsigned int reg,
                                   union vpci_val val, void *data)
{
    struct vpci_msi *msi = data;

    /* Clear low part. */
    msi->address &= ~(uint64_t)0xffffffff;
    msi->address |= val.u32;
}

/* Handlers for the high part of a 64bit address field. */
static void vpci_msi_address_upper_read(struct pci_dev *pdev, unsigned int reg,
                                        union vpci_val *val, void *data)
{
    const struct vpci_msi *msi = data;

    val->u32 = msi->address >> 32;
}

static void vpci_msi_address_upper_write(struct pci_dev *pdev, unsigned int reg,
                                         union vpci_val val, void *data)
{
    struct vpci_msi *msi = data;

    /* Clear high part. */
    msi->address &= ~((uint64_t)0xffffffff << 32);
    msi->address |= (uint64_t)val.u32 << 32;
}

/* Handlers for the data field. */
static void vpci_msi_data_read(struct pci_dev *pdev, unsigned int reg,
                               union vpci_val *val, void *data)
{
    const struct vpci_msi *msi = data;

    val->u16 = msi->data;
}

static void vpci_msi_data_write(struct pci_dev *pdev, unsigned int reg,
                                union vpci_val val, void *data)
{
    struct vpci_msi *msi = data;

    msi->data = val.u16;
}

static void vpci_msi_mask_read(struct pci_dev *pdev, unsigned int reg,
                               union vpci_val *val, void *data)
{
    const struct vpci_msi *msi = data;

    val->u32 = msi->mask;
}

static void vpci_msi_mask_write(struct pci_dev *pdev, unsigned int reg,
                                union vpci_val val, void *data)
{
    struct vpci_msi *msi = data;
    uint32_t dmask;

    dmask = msi->mask ^ val.u32;

    if ( !dmask )
        return;

    if ( msi->enabled )
    {
        unsigned int i;

        for ( i = ffs(dmask) - 1; dmask && i < msi->vectors;
              i = ffs(dmask) - 1 )
        {
            vpci_msi_arch_mask(&msi->arch, pdev, i, MASK_EXTR(val.u32, 1 << i));
            __clear_bit(i, &dmask);
        }
    }

    msi->mask = val.u32;
}

static int vpci_init_msi(struct pci_dev *pdev)
{
    uint8_t seg = pdev->seg, bus = pdev->bus;
    uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
    struct vpci_msi *msi;
    unsigned int msi_offset;
    uint16_t control;
    int ret;

    msi_offset = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSI);
    if ( !msi_offset )
        return 0;

    msi = xzalloc(struct vpci_msi);
    if ( !msi )
        return -ENOMEM;

    msi->pos = msi_offset;

    control = pci_conf_read16(seg, bus, slot, func,
                              msi_control_reg(msi_offset));

    ret = vpci_add_register(pdev, vpci_msi_control_read,
                            vpci_msi_control_write,
                            msi_control_reg(msi_offset), 2, msi);
    if ( ret )
        goto error;

    /* Get the maximum number of vectors the device supports. */
    msi->max_vectors = multi_msi_capable(control);
    ASSERT(msi->max_vectors <= 32);

    /* No PIRQ bind yet. */
    vpci_msi_arch_init(&msi->arch);

    if ( is_64bit_address(control) )
        msi->address64 = true;
    if ( is_mask_bit_support(control) )
        msi->masking = true;

    ret = vpci_add_register(pdev, vpci_msi_address_read,
                            vpci_msi_address_write,
                            msi_lower_address_reg(msi_offset), 4, msi);
    if ( ret )
        goto error;

    ret = vpci_add_register(pdev, vpci_msi_data_read, vpci_msi_data_write,
                            msi_data_reg(msi_offset, msi->address64), 2,
                            msi);
    if ( ret )
        goto error;

    if ( msi->address64 )
    {
        ret = vpci_add_register(pdev, vpci_msi_address_upper_read,
                                vpci_msi_address_upper_write,
                                msi_upper_address_reg(msi_offset), 4, msi);
        if ( ret )
            goto error;
    }

    if ( msi->masking )
    {
        ret = vpci_add_register(pdev, vpci_msi_mask_read, vpci_msi_mask_write,
                                msi_mask_bits_reg(msi_offset,
                                                  msi->address64), 4, msi);
        if ( ret )
            goto error;
    }

    pdev->vpci->msi = msi;

    return 0;

 error:
    ASSERT(ret);
    xfree(msi);
    return ret;
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

        printk("vPCI MSI information for guest %u\n", d->domain_id);

        if ( !vpci_trylock(d) )
        {
            printk("Unable to get vPCI lock, skipping\n");
            continue;
        }

        list_for_each_entry ( pdev, &d->arch.pdev_list, domain_list )
        {
            uint8_t seg = pdev->seg, bus = pdev->bus;
            uint8_t slot = PCI_SLOT(pdev->devfn), func = PCI_FUNC(pdev->devfn);
            struct vpci_msi *msi = pdev->vpci->msi;

            if ( !msi )
                continue;

            printk("Device %04x:%02x:%02x.%u\n", seg, bus, slot, func);

            printk("Enabled: %u Supports masking: %u 64-bit addresses: %u\n",
                   msi->enabled, msi->masking, msi->address64);
            printk("Max vectors: %u enabled vectors: %u\n",
                   msi->max_vectors, msi->vectors);

            vpci_msi_arch_print(&msi->arch, msi->data, msi->address);

            if ( msi->masking )
                printk("mask=%#032x\n", msi->mask);
        }
        vpci_unlock(d);
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

