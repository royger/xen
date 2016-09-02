/******************************************************************************
 * pci.c
 * 
 * Architecture-dependent PCI access functions.
 */

#include <xen/acpi.h>
#include <xen/spinlock.h>
#include <xen/pci.h>
#include <asm/io.h>
#include <xsm/xsm.h>

#include "x86_64/mmconfig.h"

static DEFINE_SPINLOCK(pci_config_lock);

uint32_t pci_conf_read(uint32_t cf8, uint8_t offset, uint8_t bytes)
{
    unsigned long flags;
    uint32_t value;

    BUG_ON((offset + bytes) > 4);

    spin_lock_irqsave(&pci_config_lock, flags);

    outl(cf8, 0xcf8);

    switch ( bytes )
    {
    case 1:
        value = inb(0xcfc + offset);
        break;
    case 2:
        value = inw(0xcfc + offset);
        break;
    case 4:
        value = inl(0xcfc + offset);
        break;
    default:
        value = 0;
        BUG();
    }

    spin_unlock_irqrestore(&pci_config_lock, flags);

    return value;
}

void pci_conf_write(uint32_t cf8, uint8_t offset, uint8_t bytes, uint32_t data)
{
    unsigned long flags;

    BUG_ON((offset + bytes) > 4);

    spin_lock_irqsave(&pci_config_lock, flags);

    outl(cf8, 0xcf8);

    switch ( bytes )
    {
    case 1:
        outb((uint8_t)data, 0xcfc + offset);
        break;
    case 2:
        outw((uint16_t)data, 0xcfc + offset);
        break;
    case 4:
        outl(data, 0xcfc + offset);
        break;
    }

    spin_unlock_irqrestore(&pci_config_lock, flags);
}

int pci_conf_write_intercept(unsigned int seg, unsigned int bdf,
                             unsigned int reg, unsigned int size,
                             uint32_t *data)
{
    struct pci_dev *pdev;
    int rc = xsm_pci_config_permission(XSM_HOOK, current->domain, bdf,
                                       reg, reg + size - 1, 1);

    if ( rc < 0 )
        return rc;
    ASSERT(!rc);

    /*
     * Avoid expensive operations when no hook is going to do anything
     * for the access anyway.
     */
    if ( reg < 64 || reg >= 256 )
        return 0;

    pcidevs_lock();

    pdev = pci_get_pdev(seg, PCI_BUS(bdf), PCI_DEVFN2(bdf));
    if ( pdev )
        rc = pci_msi_conf_write_intercept(pdev, reg, size, data);

    pcidevs_unlock();

    return rc;
}

/* Handlers to trap PCIe config accesses. */
static struct acpi_mcfg_allocation *pcie_find_mmcfg(unsigned long addr)
{
    int i;

    for ( i = 0; i < pci_mmcfg_config_num; i++ )
    {
        unsigned long start, end;

        start = pci_mmcfg_config[i].address;
        end = pci_mmcfg_config[i].address +
              ((pci_mmcfg_config[i].end_bus_number + 1) << 20);
        if ( addr >= start && addr < end )
            return &pci_mmcfg_config[i];
    }

    return NULL;
}

static struct hvm_pt_device *hw_pcie_get_device(unsigned int seg,
                                                unsigned int bus,
                                                unsigned int slot,
                                                unsigned int func)
{
    struct hvm_pt_device *dev;
    struct domain *d = current->domain;

    list_for_each_entry( dev, &d->arch.hvm_domain.pt_devices, entries )
    {
        if ( dev->pdev->seg != seg || dev->pdev->bus != bus ||
             dev->pdev->devfn != PCI_DEVFN(slot, func) )
            continue;

        return dev;
    }

    return NULL;
}

static void pcie_decode_addr(unsigned long addr, unsigned int *bus,
                             unsigned int *slot, unsigned int *func,
                             unsigned int *reg)
{

    *bus = (addr >> 20) & 0xff;
    *slot = (addr >> 15) & 0x1f;
    *func = (addr >> 12) & 0x7;
    *reg = addr & 0xfff;
}

static int pcie_range(struct vcpu *v, unsigned long addr)
{

    return pcie_find_mmcfg(addr) != NULL ? 1 : 0;
}

static int pcie_read(struct vcpu *v, unsigned long addr,
                     unsigned int len, unsigned long *pval)
{
    struct acpi_mcfg_allocation *mmcfg = pcie_find_mmcfg(addr);
    struct domain *d = v->domain;
    unsigned int seg, bus, slot, func, reg;
    struct hvm_pt_device *dev;
    uint32_t val;
    int rc;

    ASSERT(mmcfg != NULL);

    if ( len > 4 || len == 3 )
        return X86EMUL_UNHANDLEABLE;

    addr -= mmcfg->address;
    seg = mmcfg->pci_segment;
    pcie_decode_addr(addr, &bus, &slot, &func, &reg);

    read_lock(&d->arch.hvm_domain.pt_lock);
    dev = hw_pcie_get_device(seg, bus, slot, func);
    if ( dev != NULL )
    {
        rc = hvm_pt_pci_read_config(dev, reg, &val, len, true);
        if ( rc == X86EMUL_OKAY )
        {
            read_unlock(&d->arch.hvm_domain.pt_lock);
            goto out;
        }
    }
    read_unlock(&d->arch.hvm_domain.pt_lock);

    /* Pass-through */
    switch ( len )
    {
    case 1:
        val = pci_conf_read8(seg, bus, slot, func, reg);
        break;
    case 2:
        val = pci_conf_read16(seg, bus, slot, func, reg);
        break;
    case 4:
        val = pci_conf_read32(seg, bus, slot, func, reg);
        break;
    }

 out:
    *pval = val;
    return X86EMUL_OKAY;
}

static int pcie_write(struct vcpu *v, unsigned long addr,
                      unsigned int len, unsigned long val)
{
    struct acpi_mcfg_allocation *mmcfg = pcie_find_mmcfg(addr);
    struct domain *d = v->domain;
    unsigned int seg, bus, slot, func, reg;
    struct hvm_pt_device *dev;
    int rc;

    ASSERT(mmcfg != NULL);

    if ( len > 4 || len == 3 )
        return X86EMUL_UNHANDLEABLE;

    addr -= mmcfg->address;
    seg = mmcfg->pci_segment;
    pcie_decode_addr(addr, &bus, &slot, &func, &reg);

    read_lock(&d->arch.hvm_domain.pt_lock);
    dev = hw_pcie_get_device(seg, bus, slot, func);
    if ( dev != NULL )
    {
        rc = hvm_pt_pci_write_config(dev, reg, val, len, true);
        if ( rc == X86EMUL_OKAY )
        {
            read_unlock(&d->arch.hvm_domain.pt_lock);
            return rc;
        }
    }
    read_unlock(&d->arch.hvm_domain.pt_lock);

    /* Pass-through */
    switch ( len )
    {
    case 1:
        pci_conf_write8(seg, bus, slot, func, reg, val);
        break;
    case 2:
        pci_conf_write16(seg, bus, slot, func, reg, val);
        break;
    case 4:
        pci_conf_write32(seg, bus, slot, func, reg, val);
        break;
    }

    return X86EMUL_OKAY;
}

const struct hvm_mmio_ops hvm_pt_pcie_mmio_ops = {
    .check = pcie_range,
    .read = pcie_read,
    .write = pcie_write
};
