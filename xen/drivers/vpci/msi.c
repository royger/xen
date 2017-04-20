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
#include <asm/dom0_build.h>
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
    unsigned int i, vectors = 1 << ((val.word & PCI_MSI_FLAGS_QSIZE) >> 4);
    int rc;

    if ( vectors > msi->max_vectors )
        return -EINVAL;

    msi->guest_vectors = vectors;

    if ( !((val.word ^ msi->enabled) & PCI_MSI_FLAGS_ENABLE) )
        return 0;

    if ( val.word & PCI_MSI_FLAGS_ENABLE )
    {
        int index = -1;
        struct msi_info msi_info = {
            .seg = pdev->seg,
            .bus = pdev->bus,
            .devfn = pdev->devfn,
            .entry_nr = vectors,
        };

        ASSERT(!msi->enabled);

        /* Get a PIRQ. */
        rc = allocate_and_map_msi_pirq(pdev->domain, &index, &msi->pirq,
                                       &msi_info);
        if ( rc )
        {
            dprintk(XENLOG_ERR, "%04x:%02x:%02x.%u: failed to map PIRQ: %d\n",
                    pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                    PCI_FUNC(pdev->devfn), rc);
            return rc;
        }

        ASSERT(msi->pirq != -1);
        ASSERT(msi->vectors == 0);
        msi->vectors = vectors;

        for ( i = 0; i < vectors; i++ )
        {
            xen_domctl_bind_pt_irq_t bind = {
                .hvm_domid = DOMID_SELF,
                .machine_irq = msi->pirq + i,
                .irq_type = PT_IRQ_TYPE_MSI,
                .u.msi.gvec = msi_vector(msi->data) + i,
                .u.msi.gflags = msi_flags(msi->data, msi->address),
            };

            pcidevs_lock();
            rc = pt_irq_create_bind(pdev->domain, &bind);
            if ( rc )
            {
                dprintk(XENLOG_ERR,
                        "%04x:%02x:%02x.%u: failed to bind PIRQ %u: %d\n",
                        pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                        PCI_FUNC(pdev->devfn), msi->pirq + i, rc);
                spin_lock(&pdev->domain->event_lock);
                unmap_domain_pirq(pdev->domain, msi->pirq);
                spin_unlock(&pdev->domain->event_lock);
                pcidevs_unlock();
                msi->pirq = -1;
                msi->vectors = 0;
                return rc;
            }
            pcidevs_unlock();
        }
        __msi_set_enable(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                         PCI_FUNC(pdev->devfn), reg - PCI_MSI_FLAGS, 1);
        msi->enabled = true;
    }
    else
    {
        ASSERT(msi->enabled);
        __msi_set_enable(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                         PCI_FUNC(pdev->devfn), reg - PCI_MSI_FLAGS, 0);

        for ( i = 0; i < msi->vectors; i++ )
        {
            xen_domctl_bind_pt_irq_t bind = {
                .hvm_domid = DOMID_SELF,
                .machine_irq = msi->pirq + i,
                .irq_type = PT_IRQ_TYPE_MSI,
            };

            pcidevs_lock();
            pt_irq_destroy_bind(pdev->domain, &bind);
            pcidevs_unlock();
        }

        pcidevs_lock();
        spin_lock(&pdev->domain->event_lock);
        unmap_domain_pirq(pdev->domain, msi->pirq);
        spin_unlock(&pdev->domain->event_lock);
        pcidevs_unlock();

        msi->pirq = -1;
        msi->vectors = 0;
        msi->enabled = false;
    }

    return 0;
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

    while ( dmask )
    {
        unsigned int i = ffs(dmask), irq;
        struct pirq *pirq = pirq_info(current->domain, msi->pirq + i);
        struct irq_desc *desc;
        unsigned long flags;

        ASSERT(pirq);
        irq = pirq->arch.irq;
        ASSERT(irq < nr_irqs);

        desc = irq_to_desc(irq);
        ASSERT(desc);

        spin_lock_irqsave(&desc->lock, flags);
        guest_mask_msi_irq(desc, !__test_and_change_bit(i, &msi->mask));
        spin_unlock_irqrestore(&desc->lock, flags);

        __clear_bit(i, &dmask);
    }

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

    if ( !dom0_msi )
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
    msi->pirq = -1;

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

            data = msi->data;
            addr = msi->address;
            printk("vec=%#02x%7s%6s%3sassert%5s%7s dest_id=%lu pirq=%d\n",
                   (data & MSI_DATA_VECTOR_MASK) >> MSI_DATA_VECTOR_SHIFT,
                   data & MSI_DATA_DELIVERY_LOWPRI ? "lowest" : "fixed",
                   data & MSI_DATA_TRIGGER_LEVEL ? "level" : "edge",
                   data & MSI_DATA_LEVEL_ASSERT ? "" : "de",
                   addr & MSI_ADDR_DESTMODE_LOGIC ? "log" : "phys",
                   addr & MSI_ADDR_REDIRECTION_LOWPRI ? "lowest" : "cpu",
                   (addr & MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT,
                   msi->pirq);

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

