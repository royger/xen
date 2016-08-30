/*
 * io.c: Handling I/O and interrupts.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
 * Copyright (c) 2008, Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/trace.h>
#include <xen/event.h>
#include <xen/hypercall.h>
#include <asm/current.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/apic.h>
#include <asm/paging.h>
#include <asm/shadow.h>
#include <asm/p2m.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/ioreq.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/trace.h>
#include <asm/hvm/emulate.h>
#include <public/sched.h>
#include <xen/iocap.h>
#include <public/hvm/ioreq.h>

/* Set permissive mode for HVM Dom0 PCI pass-through by default */
static bool_t opt_dom0permissive = 1;
boolean_param("dom0permissive", opt_dom0permissive);

void send_timeoffset_req(unsigned long timeoff)
{
    ioreq_t p = {
        .type = IOREQ_TYPE_TIMEOFFSET,
        .size = 8,
        .count = 1,
        .dir = IOREQ_WRITE,
        .data = timeoff,
        .state = STATE_IOREQ_READY,
    };

    if ( timeoff == 0 )
        return;

    if ( hvm_broadcast_ioreq(&p, 1) != 0 )
        gprintk(XENLOG_ERR, "Unsuccessful timeoffset update\n");
}

/* Ask ioemu mapcache to invalidate mappings. */
void send_invalidate_req(void)
{
    ioreq_t p = {
        .type = IOREQ_TYPE_INVALIDATE,
        .size = 4,
        .dir = IOREQ_WRITE,
        .data = ~0UL, /* flush all */
    };

    if ( hvm_broadcast_ioreq(&p, 0) != 0 )
        gprintk(XENLOG_ERR, "Unsuccessful map-cache invalidate\n");
}

int handle_mmio(void)
{
    struct hvm_emulate_ctxt ctxt;
    struct vcpu *curr = current;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    int rc;

    ASSERT(!is_pvh_vcpu(curr));

    hvm_emulate_prepare(&ctxt, guest_cpu_user_regs());

    rc = hvm_emulate_one(&ctxt);

    if ( hvm_vcpu_io_need_completion(vio) || vio->mmio_retry )
        vio->io_completion = HVMIO_mmio_completion;
    else
        vio->mmio_access = (struct npfec){};

    switch ( rc )
    {
    case X86EMUL_UNHANDLEABLE:
        hvm_dump_emulation_state(XENLOG_G_WARNING "MMIO", &ctxt);
        return 0;
    case X86EMUL_EXCEPTION:
        if ( ctxt.exn_pending )
            hvm_inject_trap(&ctxt.trap);
        break;
    default:
        break;
    }

    hvm_emulate_writeback(&ctxt);

    return 1;
}

int handle_mmio_with_translation(unsigned long gla, unsigned long gpfn,
                                 struct npfec access)
{
    struct hvm_vcpu_io *vio = &current->arch.hvm_vcpu.hvm_io;

    vio->mmio_access = access.gla_valid &&
                       access.kind == npfec_kind_with_gla
                       ? access : (struct npfec){};
    vio->mmio_gla = gla & PAGE_MASK;
    vio->mmio_gpfn = gpfn;
    return handle_mmio();
}

int handle_pio(uint16_t port, unsigned int size, int dir)
{
    struct vcpu *curr = current;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    unsigned long data;
    int rc;

    ASSERT((size - 1) < 4 && size != 3);

    if ( dir == IOREQ_WRITE )
        data = guest_cpu_user_regs()->eax;

    rc = hvmemul_do_pio_buffer(port, size, dir, &data);

    if ( hvm_vcpu_io_need_completion(vio) )
        vio->io_completion = HVMIO_pio_completion;

    switch ( rc )
    {
    case X86EMUL_OKAY:
        if ( dir == IOREQ_READ )
        {
            if ( size == 4 ) /* Needs zero extension. */
                guest_cpu_user_regs()->rax = (uint32_t)data;
            else
                memcpy(&guest_cpu_user_regs()->rax, &data, size);
        }
        break;
    case X86EMUL_RETRY:
        /* We should not advance RIP/EIP if the domain is shutting down */
        if ( curr->domain->is_shutting_down )
            return 0;

        break;
    default:
        gdprintk(XENLOG_ERR, "Weird HVM ioemulation status %d.\n", rc);
        domain_crash(curr->domain);
        break;
    }

    return 1;
}

static bool_t dpci_portio_accept(const struct hvm_io_handler *handler,
                                 const ioreq_t *p)
{
    struct vcpu *curr = current;
    const struct domain_iommu *dio = dom_iommu(curr->domain);
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    struct g2m_ioport *g2m_ioport;
    unsigned int start, end;

    list_for_each_entry( g2m_ioport, &dio->arch.g2m_ioport_list, list )
    {
        start = g2m_ioport->gport;
        end = start + g2m_ioport->np;
        if ( (p->addr >= start) && (p->addr + p->size <= end) )
        {
            vio->g2m_ioport = g2m_ioport;
            return 1;
        }
    }

    return 0;
}

static int dpci_portio_read(const struct hvm_io_handler *handler,
                            uint64_t addr,
                            uint32_t size,
                            uint64_t *data)
{
    struct hvm_vcpu_io *vio = &current->arch.hvm_vcpu.hvm_io;
    const struct g2m_ioport *g2m_ioport = vio->g2m_ioport;
    unsigned int mport = (addr - g2m_ioport->gport) + g2m_ioport->mport;

    switch ( size )
    {
    case 1:
        *data = inb(mport);
        break;
    case 2:
        *data = inw(mport);
        break;
    case 4:
        *data = inl(mport);
        break;
    default:
        BUG();
    }

    return X86EMUL_OKAY;
}

static int dpci_portio_write(const struct hvm_io_handler *handler,
                             uint64_t addr,
                             uint32_t size,
                             uint64_t data)
{
    struct hvm_vcpu_io *vio = &current->arch.hvm_vcpu.hvm_io;
    const struct g2m_ioport *g2m_ioport = vio->g2m_ioport;
    unsigned int mport = (addr - g2m_ioport->gport) + g2m_ioport->mport;

    switch ( size )
    {
    case 1:
        outb(data, mport);
        break;
    case 2:
        outw(data, mport);
        break;
    case 4:
        outl(data, mport);
        break;
    default:
        BUG();
    }

    return X86EMUL_OKAY;
}

static bool_t hw_dpci_portio_accept(const struct hvm_io_handler *handler,
                                    const ioreq_t *p)
{
    if ( (p->addr == 0xcf8 && p->size == 4) || (p->addr & 0xfffc) == 0xcfc)
    {
        return 1;
    }

    return 0;
}

static struct hvm_pt_device *hw_dpci_get_device(struct domain *d)
{
    uint8_t bus, slot, func;
    uint32_t addr;
    struct hvm_pt_device *dev;

    /* Decode bus, slot and func. */
    addr = CF8_BDF(d->arch.pci_cf8);
    bus = PCI_BUS(addr);
    slot = PCI_SLOT(addr);
    func = PCI_FUNC(addr);

    list_for_each_entry( dev, &d->arch.hvm_domain.pt_devices, entries )
    {
        if ( dev->pdev->seg != 0 || dev->pdev->bus != bus ||
             dev->pdev->devfn != PCI_DEVFN(slot,func) )
            continue;

        return dev;
    }

    return NULL;
}

/* Dispatchers */

/* Find emulate register group entry */
struct hvm_pt_reg_group *hvm_pt_find_reg_grp(struct hvm_pt_device *d,
                                             uint32_t address)
{
    struct hvm_pt_reg_group *entry = NULL;

    /* Find register group entry */
    list_for_each_entry( entry, &d->register_groups, entries )
    {
        /* check address */
        if ( (entry->base_offset <= address)
             && ((entry->base_offset + entry->size) > address) )
            return entry;
    }

    /* Group entry not found */
    return NULL;
}

/* Find emulate register entry */
struct hvm_pt_reg *hvm_pt_find_reg(struct hvm_pt_reg_group *reg_grp,
                                   uint32_t address)
{
    struct hvm_pt_reg *reg_entry = NULL;
    struct hvm_pt_reg_handler *handler = NULL;
    uint32_t real_offset = 0;

    /* Find register entry */
    list_for_each_entry( reg_entry, &reg_grp->registers, entries )
    {
        handler = reg_entry->handler;
        real_offset = reg_grp->base_offset + handler->offset;
        /* Check address */
        if ( (real_offset <= address)
             && ((real_offset + handler->size) > address) )
            return reg_entry;
    }

    return NULL;
}

static int hvm_pt_pci_config_access_check(struct hvm_pt_device *d,
                                          uint32_t addr, int len)
{
    /* Check offset range */
    if ( addr >= 0xFF )
    {
        printk_pdev(d->pdev, XENLOG_DEBUG,
            "failed to access register with offset exceeding 0xFF. "
            "(addr: 0x%02x, len: %d)\n", addr, len);
        return -EDOM;
    }

    /* Check read size */
    if ( (len != 1) && (len != 2) && (len != 4) )
    {
        printk_pdev(d->pdev, XENLOG_DEBUG,
            "failed to access register with invalid access length. "
            "(addr: 0x%02x, len: %d)\n", addr, len);
        return -EINVAL;
    }

    /* Check offset alignment */
    if ( addr & (len - 1) )
    {
        printk_pdev(d->pdev, XENLOG_DEBUG,
            "failed to access register with invalid access size "
            "alignment. (addr: 0x%02x, len: %d)\n", addr, len);
        return -EINVAL;
    }

    return 0;
}

static int hvm_pt_pci_read_config(struct hvm_pt_device *d, uint32_t addr,
                                  uint32_t *data, int len)
{
    uint32_t val = 0;
    struct hvm_pt_reg_group *reg_grp_entry = NULL;
    struct hvm_pt_reg *reg_entry = NULL;
    int rc = 0;
    int emul_len = 0;
    uint32_t find_addr = addr;
    unsigned int seg = d->pdev->seg;
    unsigned int bus = d->pdev->bus;
    unsigned int slot = PCI_SLOT(d->pdev->devfn);
    unsigned int func = PCI_FUNC(d->pdev->devfn);

    /* Sanity checks. */
    if ( hvm_pt_pci_config_access_check(d, addr, len) )
        return X86EMUL_UNHANDLEABLE;

    /* Find register group entry. */
    reg_grp_entry = hvm_pt_find_reg_grp(d, addr);
    if ( reg_grp_entry == NULL )
        return X86EMUL_UNHANDLEABLE;

    /* Read I/O device register value. */
    switch( len )
    {
    case 1:
        val = pci_conf_read8(seg, bus, slot, func, addr);
        break;
    case 2:
        val = pci_conf_read16(seg, bus, slot, func, addr);
        break;
    case 4:
        val = pci_conf_read32(seg, bus, slot, func, addr);
        break;
    default:
        BUG();
    }

    /* Adjust the read value to appropriate CFC-CFF window. */
    val <<= (addr & 3) << 3;
    emul_len = len;

    /* Loop around the guest requested size. */
    while ( emul_len > 0 )
    {
        /* Find register entry to be emulated. */
        reg_entry = hvm_pt_find_reg(reg_grp_entry, find_addr);
        if ( reg_entry )
        {
            struct hvm_pt_reg_handler *handler = reg_entry->handler;
            uint32_t real_offset = reg_grp_entry->base_offset + handler->offset;
            uint32_t valid_mask = 0xFFFFFFFF >> ((4 - emul_len) << 3);
            uint8_t *ptr_val = NULL;

            valid_mask <<= (find_addr - real_offset) << 3;
            ptr_val = (uint8_t *)&val + (real_offset & 3);

            /* Do emulation based on register size. */
            switch ( handler->size )
            {
            case 1:
                if ( handler->u.b.read )
                    rc = handler->u.b.read(d, reg_entry, ptr_val, valid_mask);
                break;
            case 2:
                if ( handler->u.w.read )
                    rc = handler->u.w.read(d, reg_entry, (uint16_t *)ptr_val,
                                           valid_mask);
                break;
            case 4:
                if ( handler->u.dw.read )
                    rc = handler->u.dw.read(d, reg_entry, (uint32_t *)ptr_val,
                                            valid_mask);
                break;
            }

            if ( rc < 0 )
            {
                gdprintk(XENLOG_WARNING,
                         "Invalid read emulation, shutting down domain\n");
                domain_crash(current->domain);
                return X86EMUL_UNHANDLEABLE;
            }

            /* Calculate next address to find. */
            emul_len -= handler->size;
            if ( emul_len > 0 )
                find_addr = real_offset + handler->size;
        }
        else
        {
            /* Nothing to do with passthrough type register */
            emul_len--;
            find_addr++;
        }
    }

    /* Need to shift back before returning them to pci bus emulator */
    val >>= ((addr & 3) << 3);
    *data = val;

    return X86EMUL_OKAY;
}

static int hvm_pt_pci_write_config(struct hvm_pt_device *d, uint32_t addr,
                                    uint32_t val, int len)
{
    int index = 0;
    struct hvm_pt_reg_group *reg_grp_entry = NULL;
    int rc = 0;
    uint32_t read_val = 0, wb_mask;
    int emul_len = 0;
    struct hvm_pt_reg *reg_entry = NULL;
    uint32_t find_addr = addr;
    struct hvm_pt_reg_handler *handler = NULL;
    bool wp_flag = false;
    unsigned int seg = d->pdev->seg;
    unsigned int bus = d->pdev->bus;
    unsigned int slot = PCI_SLOT(d->pdev->devfn);
    unsigned int func = PCI_FUNC(d->pdev->devfn);

    /* Sanity checks. */
    if ( hvm_pt_pci_config_access_check(d, addr, len) )
        return X86EMUL_UNHANDLEABLE;

    /* Find register group entry. */
    reg_grp_entry = hvm_pt_find_reg_grp(d, addr);
    if ( reg_grp_entry == NULL )
        return X86EMUL_UNHANDLEABLE;

    /* Read I/O device register value. */
    switch( len )
    {
    case 1:
        read_val = pci_conf_read8(seg, bus, slot, func, addr);
        break;
    case 2:
        read_val = pci_conf_read16(seg, bus, slot, func, addr);
        break;
    case 4:
        read_val = pci_conf_read32(seg, bus, slot, func, addr);
        break;
    default:
        BUG();
    }
    wb_mask = 0xFFFFFFFF >> ((4 - len) << 3);

    /* Adjust the read and write value to appropriate CFC-CFF window */
    read_val <<= (addr & 3) << 3;
    val <<= (addr & 3) << 3;
    emul_len = len;

    /* Loop around the guest requested size */
    while ( emul_len > 0 )
    {
        /* Find register entry to be emulated */
        reg_entry = hvm_pt_find_reg(reg_grp_entry, find_addr);
        if ( reg_entry )
        {
            handler = reg_entry->handler;
            uint32_t real_offset = reg_grp_entry->base_offset + handler->offset;
            uint32_t valid_mask = 0xFFFFFFFF >> ((4 - emul_len) << 3);
            uint8_t *ptr_val = NULL;
            uint32_t wp_mask = handler->emu_mask | handler->ro_mask;

            valid_mask <<= (find_addr - real_offset) << 3;
            ptr_val = (uint8_t *)&val + (real_offset & 3);
            if ( !d->permissive )
                wp_mask |= handler->res_mask;
            if ( wp_mask == (0xFFFFFFFF >> ((4 - handler->size) << 3)) )
                wb_mask &= ~((wp_mask >> ((find_addr - real_offset) << 3))
                             << ((len - emul_len) << 3));

            /* Do emulation based on register size */
            switch ( handler->size )
            {
            case 1:
                if ( handler->u.b.write )
                    rc = handler->u.b.write(d, reg_entry, ptr_val,
                                            read_val >> ((real_offset & 3) << 3),
                                            valid_mask);
                break;
            case 2:
                if ( handler->u.w.write )
                    rc = handler->u.w.write(d, reg_entry, (uint16_t *)ptr_val,
                                            (read_val >> ((real_offset & 3) << 3)),
                                            valid_mask);
                break;
            case 4:
                if ( handler->u.dw.write )
                    rc = handler->u.dw.write(d, reg_entry, (uint32_t *)ptr_val,
                                             (read_val >> ((real_offset & 3) << 3)),
                                             valid_mask);
                break;
            }

            if ( rc < 0 )
            {
                gdprintk(XENLOG_WARNING,
                         "Invalid write emulation, shutting down domain\n");
                domain_crash(current->domain);
                return X86EMUL_UNHANDLEABLE;
            }

            /* Calculate next address to find */
            emul_len -= handler->size;
            if ( emul_len > 0 )
                find_addr = real_offset + handler->size;
        }
        else
        {
            /* Nothing to do with passthrough type register */
            if ( !d->permissive )
            {
                wb_mask &= ~(0xff << ((len - emul_len) << 3));
                /*
                 * Unused BARs will make it here, but we don't want to issue
                 * warnings for writes to them (bogus writes get dealt with
                 * above).
                 */
                if ( index < 0 )
                    wp_flag = true;
            }
            emul_len--;
            find_addr++;
        }
    }

    /* Need to shift back before passing them to xen_host_pci_set_block */
    val >>= (addr & 3) << 3;

    if ( wp_flag && !d->permissive_warned )
    {
        d->permissive_warned = true;
        gdprintk(XENLOG_WARNING,
          "Write-back to unknown field 0x%02x (partially) inhibited (0x%0*x)\n",
          addr, len * 2, wb_mask);
        gdprintk(XENLOG_WARNING,
          "If the device doesn't work, try enabling permissive mode\n");
        gdprintk(XENLOG_WARNING,
          "(unsafe) and if it helps report the problem to xen-devel\n");
    }
    for ( index = 0; wb_mask; index += len )
    {
        /* Unknown regs are passed through */
        while ( !(wb_mask & 0xff) )
        {
            index++;
            wb_mask >>= 8;
        }
        len = 0;
        do {
            len++;
            wb_mask >>= 8;
        } while ( wb_mask & 0xff );

        switch( len )
        {
        case 1:
        {
            uint8_t value;
            memcpy(&value, (uint8_t *)&val + index, 1);
            pci_conf_write8(seg, bus, slot, func, addr + index, value);
            break;
        }
        case 2:
        {
            uint16_t value;
            memcpy(&value, (uint8_t *)&val + index, 2);
            pci_conf_write16(seg, bus, slot, func, addr + index, value);
            break;
        }
        case 4:
        {
            uint32_t value;
            memcpy(&value, (uint8_t *)&val + index, 4);
            pci_conf_write32(seg, bus, slot, func, addr + index, value);
            break;
        }
        default:
            BUG();
        }
    }
    return X86EMUL_OKAY;
}

static int hw_dpci_portio_read(const struct hvm_io_handler *handler,
                            uint64_t addr,
                            uint32_t size,
                            uint64_t *data)
{
    struct domain *currd = current->domain;
    struct hvm_pt_device *dev;
    uint32_t data32;
    uint8_t reg;
    int rc;

    if ( addr == 0xcf8 )
    {
        ASSERT(size == 4);
        *data = currd->arch.pci_cf8;
        return X86EMUL_OKAY;
    }

    ASSERT((addr & 0xfffc) == 0xcfc);
    size = min(size, 4 - ((uint32_t)addr & 3));
    if ( size == 3 )
        size = 2;

    read_lock(&currd->arch.hvm_domain.pt_lock);
    dev = hw_dpci_get_device(currd);
    if ( dev != NULL )
    {
        reg = (currd->arch.pci_cf8 & 0xfc) | (addr & 0x3);
        rc = hvm_pt_pci_read_config(dev, reg, &data32, size);
        if ( rc == X86EMUL_OKAY )
        {
            read_unlock(&currd->arch.hvm_domain.pt_lock);
            *data = data32;
            return rc;
        }
    }
    read_unlock(&currd->arch.hvm_domain.pt_lock);

    if ( pci_cfg_ok(currd, addr & 3, size, NULL) )
        *data = pci_conf_read(currd->arch.pci_cf8, addr & 3, size);

    return X86EMUL_OKAY;
}

static int hw_dpci_portio_write(const struct hvm_io_handler *handler,
                                uint64_t addr,
                                uint32_t size,
                                uint64_t data)
{
    struct domain *currd = current->domain;
    struct hvm_pt_device *dev;
    uint32_t data32;
    uint8_t reg;
    int rc;

    if ( addr == 0xcf8 )
    {
            ASSERT(size == 4);
            currd->arch.pci_cf8 = data;
            return X86EMUL_OKAY;
    }

    ASSERT((addr & 0xfffc) == 0xcfc);
    size = min(size, 4 - ((uint32_t)addr & 3));
    if ( size == 3 )
        size = 2;
    data32 = data;

    read_lock(&currd->arch.hvm_domain.pt_lock);
    dev = hw_dpci_get_device(currd);
    if ( dev != NULL )
    {
        reg = (currd->arch.pci_cf8 & 0xfc) | (addr & 0x3);
        rc = hvm_pt_pci_write_config(dev, reg, data32, size);
        if ( rc == X86EMUL_OKAY )
        {
            read_unlock(&currd->arch.hvm_domain.pt_lock);
            return rc;
        }
    }
    read_unlock(&currd->arch.hvm_domain.pt_lock);

    if ( pci_cfg_ok(currd, addr & 3, size, &data32) )
        pci_conf_write(currd->arch.pci_cf8, addr & 3, size, data);

    return X86EMUL_OKAY;
}

static void hvm_pt_free_device(struct hvm_pt_device *dev)
{
    struct hvm_pt_reg_group *group, *g;

    list_for_each_entry_safe( group, g, &dev->register_groups, entries )
    {
        struct hvm_pt_reg *reg, *r;

        list_for_each_entry_safe( reg, r, &group->registers, entries )
        {
            list_del(&reg->entries);
            xfree(reg);
        }

        list_del(&group->entries);
        xfree(group);
    }

    xfree(dev);
}

static int hvm_pt_add_register(struct hvm_pt_device *dev,
                               struct hvm_pt_reg_group *group,
                               struct hvm_pt_reg_handler *handler)
{
    struct pci_dev *pdev = dev->pdev;
    struct hvm_pt_reg *reg;

    reg = xmalloc(struct hvm_pt_reg);
    if ( reg == NULL )
        return -ENOMEM;

    memset(reg, 0, sizeof(*reg));
    reg->handler = handler;
    if ( handler->init != NULL )
    {
        uint32_t host_mask, size_mask, data = 0;
        uint8_t seg, bus, slot, func;
        unsigned int offset;
        uint32_t val;
        int rc;

        /* Initialize emulate register */
        rc = handler->init(dev, reg->handler,
                           group->base_offset + reg->handler->offset, &data);
        if ( rc < 0 )
            return rc;

        if ( data == HVM_PT_INVALID_REG )
        {
            xfree(reg);
            return 0;
        }

        /* Sync up the data to val */
        offset = group->base_offset + reg->handler->offset;
        size_mask = 0xFFFFFFFF >> ((4 - reg->handler->size) << 3);

        seg = pdev->seg;
        bus = pdev->bus;
        slot = PCI_SLOT(pdev->devfn);
        func = PCI_FUNC(pdev->devfn);

        switch ( reg->handler->size )
        {
        case 1:
            val = pci_conf_read8(seg, bus, slot, func, offset);
            break;
        case 2:
            val = pci_conf_read16(seg, bus, slot, func, offset);
            break;
        case 4:
            val = pci_conf_read32(seg, bus, slot, func, offset);
            break;
        default:
            BUG();
        }

        /*
         * Set bits in emu_mask are the ones we emulate. The reg shall
         * contain the emulated view of the guest - therefore we flip
         * the mask to mask out the host values (which reg initially
         * has).
         */
        host_mask = size_mask & ~reg->handler->emu_mask;

        if ( (data & host_mask) != (val & host_mask) )
        {
            uint32_t new_val;

            /* Mask out host (including past size). */
            new_val = val & host_mask;
            /* Merge emulated ones (excluding the non-emulated ones). */
            new_val |= data & host_mask;
            /*
             * Leave intact host and emulated values past the size -
             * even though we do not care as we write per reg->size
             * granularity, but for the logging below lets have the
             * proper value.
             */
            new_val |= ((val | data)) & ~size_mask;
            printk_pdev(pdev, XENLOG_ERR,
"offset 0x%04x mismatch! Emulated=0x%04x, host=0x%04x, syncing to 0x%04x.\n",
                        offset, data, val, new_val);
            val = new_val;
        }
        else
            val = data;

        if ( val & ~size_mask )
        {
            printk_pdev(pdev, XENLOG_ERR,
                    "Offset 0x%04x:0x%04x expands past register size(%d)!\n",
                        offset, val, reg->handler->size);
            return -EINVAL;
        }

        reg->val.dword = val;
    }
    list_add_tail(&reg->entries, &group->registers);

    return 0;
}

static struct hvm_pt_handler_init *hwdom_pt_handlers[] = {
    &hvm_pt_bar_init,
    &hvm_pt_vf_bar_init,
};

int hwdom_add_device(struct pci_dev *pdev)
{
    struct domain *d = pdev->domain;
    struct hvm_pt_device *dev;
    int j, i, rc;

    ASSERT( is_hardware_domain(d) );
    ASSERT( pcidevs_locked() );

    dev = xmalloc(struct hvm_pt_device);
    if ( dev == NULL )
        return -ENOMEM;

    memset(dev, 0 , sizeof(*dev));

    dev->pdev = pdev;
    INIT_LIST_HEAD(&dev->register_groups);

    dev->permissive = opt_dom0permissive;

    for ( j = 0; j < ARRAY_SIZE(hwdom_pt_handlers); j++ )
    {
        struct hvm_pt_handler_init *handler_init = hwdom_pt_handlers[j];
        struct hvm_pt_reg_group *group;

        group = xmalloc(struct hvm_pt_reg_group);
        if ( group == NULL )
        {
            xfree(dev);
            return -ENOMEM;
        }
        INIT_LIST_HEAD(&group->registers);

        rc = handler_init->init(dev, group);
        if ( rc == 0 )
        {
            for ( i = 0; handler_init->handlers[i].size != 0; i++ )
            {
                int rc;

                rc = hvm_pt_add_register(dev, group,
                                         &handler_init->handlers[i]);
                if ( rc )
                {
                    printk_pdev(pdev, XENLOG_ERR, "error adding register: %d\n",
                                rc);
                    hvm_pt_free_device(dev);
                    return rc;
                }
            }

            list_add_tail(&group->entries, &dev->register_groups);
        }
        else
            xfree(group);
    }

    write_lock(&d->arch.hvm_domain.pt_lock);
    list_add_tail(&dev->entries, &d->arch.hvm_domain.pt_devices);
    write_unlock(&d->arch.hvm_domain.pt_lock);
    printk_pdev(pdev, XENLOG_DEBUG, "added for pass-through\n");

    return 0;
}

static const struct hvm_io_ops dpci_portio_ops = {
    .accept = dpci_portio_accept,
    .read = dpci_portio_read,
    .write = dpci_portio_write
};

static const struct hvm_io_ops hw_dpci_portio_ops = {
    .accept = hw_dpci_portio_accept,
    .read = hw_dpci_portio_read,
    .write = hw_dpci_portio_write
};

void register_dpci_portio_handler(struct domain *d)
{
    struct hvm_io_handler *handler = hvm_next_io_handler(d);

    if ( handler == NULL )
        return;

    handler->type = IOREQ_TYPE_PIO;
    if ( is_hardware_domain(d) )
        handler->ops = &hw_dpci_portio_ops;
    else
        handler->ops = &dpci_portio_ops;
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
