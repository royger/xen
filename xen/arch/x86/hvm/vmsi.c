/*
 *  Copyright (C) 2001  MandrakeSoft S.A.
 *
 *    MandrakeSoft S.A.
 *    43, rue d'Aboukir
 *    75002 Paris - France
 *    http://www.linux-mandrake.com/
 *    http://www.mandrakesoft.com/
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * Support for virtual MSI logic
 * Will be merged it with virtual IOAPIC logic, since most is the same
*/

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/xmalloc.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <public/hvm/ioreq.h>
#include <asm/hvm/io.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/support.h>
#include <asm/current.h>
#include <asm/event.h>
#include <asm/io_apic.h>
#include <asm/p2m.h>

static void vmsi_inj_irq(
    struct vlapic *target,
    uint8_t vector,
    uint8_t trig_mode,
    uint8_t delivery_mode)
{
    HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "vmsi_inj_irq: vec %02x trig %d dm %d\n",
                vector, trig_mode, delivery_mode);

    switch ( delivery_mode )
    {
    case dest_Fixed:
    case dest_LowestPrio:
        vlapic_set_irq(target, vector, trig_mode);
        break;
    default:
        BUG();
    }
}

int vmsi_deliver(
    struct domain *d, int vector,
    uint8_t dest, uint8_t dest_mode,
    uint8_t delivery_mode, uint8_t trig_mode)
{
    struct vlapic *target;
    struct vcpu *v;

    switch ( delivery_mode )
    {
    case dest_LowestPrio:
        target = vlapic_lowest_prio(d, NULL, 0, dest, dest_mode);
        if ( target != NULL )
        {
            vmsi_inj_irq(target, vector, trig_mode, delivery_mode);
            break;
        }
        HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "null MSI round robin: vector=%02x\n",
                    vector);
        return -ESRCH;

    case dest_Fixed:
        for_each_vcpu ( d, v )
            if ( vlapic_match_dest(vcpu_vlapic(v), NULL,
                                   0, dest, dest_mode) )
                vmsi_inj_irq(vcpu_vlapic(v), vector,
                             trig_mode, delivery_mode);
        break;

    default:
        printk(XENLOG_G_WARNING
               "%pv: Unsupported MSI delivery mode %d for Dom%d\n",
               current, delivery_mode, d->domain_id);
        return -EINVAL;
    }

    return 0;
}

void vmsi_deliver_pirq(struct domain *d, const struct hvm_pirq_dpci *pirq_dpci)
{
    uint32_t flags = pirq_dpci->gmsi.gflags;
    int vector = pirq_dpci->gmsi.gvec;
    uint8_t dest = (uint8_t)flags;
    uint8_t dest_mode = !!(flags & VMSI_DM_MASK);
    uint8_t delivery_mode = (flags & VMSI_DELIV_MASK)
        >> GFLAGS_SHIFT_DELIV_MODE;
    uint8_t trig_mode = (flags&VMSI_TRIG_MODE) >> GFLAGS_SHIFT_TRG_MODE;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC,
                "msi: dest=%x dest_mode=%x delivery_mode=%x "
                "vector=%x trig_mode=%x\n",
                dest, dest_mode, delivery_mode, vector, trig_mode);

    ASSERT(pirq_dpci->flags & HVM_IRQ_DPCI_GUEST_MSI);

    vmsi_deliver(d, vector, dest, dest_mode, delivery_mode, trig_mode);
}

/* Return value, -1 : multi-dests, non-negative value: dest_vcpu_id */
int hvm_girq_dest_2_vcpu_id(struct domain *d, uint8_t dest, uint8_t dest_mode)
{
    int dest_vcpu_id = -1, w = 0;
    struct vcpu *v;
    
    if ( d->max_vcpus == 1 )
        return 0;
 
    for_each_vcpu ( d, v )
    {
        if ( vlapic_match_dest(vcpu_vlapic(v), NULL, 0, dest, dest_mode) ) 
        {
            w++;
            dest_vcpu_id = v->vcpu_id;
        }
    }
    if ( w > 1 )
        return -1;

    return dest_vcpu_id;
}

/* MSI-X mask bit hypervisor interception */
struct msixtbl_entry
{
    struct list_head list;
    atomic_t refcnt;    /* how many bind_pt_irq called for the device */

    /* TODO: resolve the potential race by destruction of pdev */
    struct pci_dev *pdev;
    unsigned long gtable;       /* gpa of msix table */
    DECLARE_BITMAP(table_flags, MAX_MSIX_TABLE_ENTRIES);
#define MAX_MSIX_ACC_ENTRIES 3
    unsigned int table_len;
    struct { 
        uint32_t msi_ad[3];	/* Shadow of address low, high and data */
    } gentries[MAX_MSIX_ACC_ENTRIES];
    DECLARE_BITMAP(acc_valid, 3 * MAX_MSIX_ACC_ENTRIES);
#define acc_bit(what, ent, slot, idx) \
        what##_bit((slot) * 3 + (idx), (ent)->acc_valid)
    struct rcu_head rcu;
};

static DEFINE_RCU_READ_LOCK(msixtbl_rcu_lock);

/*
 * MSI-X table infrastructure is dynamically initialised when an MSI-X capable
 * device is passed through to a domain, rather than unconditionally for all
 * domains.
 */
static bool msixtbl_initialised(const struct domain *d)
{
    return !!d->arch.hvm_domain.msixtbl_list.next;
}

static struct msixtbl_entry *msixtbl_find_entry(
    struct vcpu *v, unsigned long addr)
{
    struct msixtbl_entry *entry;
    struct domain *d = v->domain;

    list_for_each_entry( entry, &d->arch.hvm_domain.msixtbl_list, list )
        if ( addr >= entry->gtable &&
             addr < entry->gtable + entry->table_len )
            return entry;

    return NULL;
}

static struct msi_desc *msixtbl_addr_to_desc(
    const struct msixtbl_entry *entry, unsigned long addr)
{
    unsigned int nr_entry;
    struct msi_desc *desc;

    if ( !entry || !entry->pdev )
        return NULL;

    nr_entry = (addr - entry->gtable) / PCI_MSIX_ENTRY_SIZE;

    list_for_each_entry( desc, &entry->pdev->msi_list, list )
        if ( desc->msi_attrib.type == PCI_CAP_ID_MSIX &&
             desc->msi_attrib.entry_nr == nr_entry )
            return desc;

    return NULL;
}

static int msixtbl_read(const struct hvm_io_handler *handler,
                        uint64_t address, uint32_t len, uint64_t *pval)
{
    unsigned long offset;
    struct msixtbl_entry *entry;
    unsigned int nr_entry, index;
    int r = X86EMUL_UNHANDLEABLE;

    if ( (len != 4 && len != 8) || (address & (len - 1)) )
        return r;

    rcu_read_lock(&msixtbl_rcu_lock);

    entry = msixtbl_find_entry(current, address);
    if ( !entry )
        goto out;
    offset = address & (PCI_MSIX_ENTRY_SIZE - 1);

    if ( offset != PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET )
    {
        nr_entry = (address - entry->gtable) / PCI_MSIX_ENTRY_SIZE;
        index = offset / sizeof(uint32_t);
        if ( nr_entry >= MAX_MSIX_ACC_ENTRIES ||
             !acc_bit(test, entry, nr_entry, index) )
            goto out;
        *pval = entry->gentries[nr_entry].msi_ad[index];
        if ( len == 8 )
        {
            if ( index )
                offset = PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET;
            else if ( acc_bit(test, entry, nr_entry, 1) )
                *pval |= (u64)entry->gentries[nr_entry].msi_ad[1] << 32;
            else
                goto out;
        }
    }
    if ( offset == PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET )
    {
        const struct msi_desc *msi_desc = msixtbl_addr_to_desc(entry, address);

        if ( !msi_desc )
            goto out;
        if ( len == 4 )
            *pval = MASK_INSR(msi_desc->msi_attrib.guest_masked,
                              PCI_MSIX_VECTOR_BITMASK);
        else
            *pval |= (u64)MASK_INSR(msi_desc->msi_attrib.guest_masked,
                                    PCI_MSIX_VECTOR_BITMASK) << 32;
    }
    
    r = X86EMUL_OKAY;
out:
    rcu_read_unlock(&msixtbl_rcu_lock);
    return r;
}

static int msixtbl_write(struct vcpu *v, unsigned long address,
                         unsigned int len, unsigned long val)
{
    unsigned long offset;
    struct msixtbl_entry *entry;
    const struct msi_desc *msi_desc;
    unsigned int nr_entry, index;
    int r = X86EMUL_UNHANDLEABLE;
    unsigned long flags;
    struct irq_desc *desc;

    if ( (len != 4 && len != 8) || (address & (len - 1)) )
        return r;

    rcu_read_lock(&msixtbl_rcu_lock);

    entry = msixtbl_find_entry(v, address);
    if ( !entry )
        goto out;
    nr_entry = (address - entry->gtable) / PCI_MSIX_ENTRY_SIZE;

    offset = address & (PCI_MSIX_ENTRY_SIZE - 1);
    if ( offset != PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET )
    {
        index = offset / sizeof(uint32_t);
        if ( nr_entry < MAX_MSIX_ACC_ENTRIES ) 
        {
            entry->gentries[nr_entry].msi_ad[index] = val;
            acc_bit(set, entry, nr_entry, index);
            if ( len == 8 && !index )
            {
                entry->gentries[nr_entry].msi_ad[1] = val >> 32;
                acc_bit(set, entry, nr_entry, 1);
            }
        }
        set_bit(nr_entry, &entry->table_flags);
        if ( len != 8 || !index )
            goto out;
        val >>= 32;
        address += 4;
    }

    /* Exit to device model when unmasking and address/data got modified. */
    if ( !(val & PCI_MSIX_VECTOR_BITMASK) &&
         test_and_clear_bit(nr_entry, &entry->table_flags) )
    {
        v->arch.hvm_vcpu.hvm_io.msix_unmask_address = address;
        goto out;
    }

    msi_desc = msixtbl_addr_to_desc(entry, address);
    if ( !msi_desc || msi_desc->irq < 0 )
        goto out;
    
    desc = irq_to_desc(msi_desc->irq);
    if ( !desc )
        goto out;

    spin_lock_irqsave(&desc->lock, flags);

    if ( !desc->msi_desc )
        goto unlock;

    ASSERT(msi_desc == desc->msi_desc);
   
    guest_mask_msi_irq(desc, !!(val & PCI_MSIX_VECTOR_BITMASK));

unlock:
    spin_unlock_irqrestore(&desc->lock, flags);
    if ( len == 4 )
        r = X86EMUL_OKAY;

out:
    rcu_read_unlock(&msixtbl_rcu_lock);
    return r;
}

static int _msixtbl_write(const struct hvm_io_handler *handler,
                          uint64_t address, uint32_t len, uint64_t val)
{
    return msixtbl_write(current, address, len, val);
}

static bool_t msixtbl_range(const struct hvm_io_handler *handler,
                            const ioreq_t *r)
{
    struct vcpu *curr = current;
    unsigned long addr = r->addr;
    const struct msi_desc *desc;

    ASSERT(r->type == IOREQ_TYPE_COPY);

    rcu_read_lock(&msixtbl_rcu_lock);
    desc = msixtbl_addr_to_desc(msixtbl_find_entry(curr, addr), addr);
    rcu_read_unlock(&msixtbl_rcu_lock);

    if ( desc )
        return 1;

    if ( r->state == STATE_IOREQ_READY && r->dir == IOREQ_WRITE )
    {
        unsigned int size = r->size;

        if ( !r->data_is_ptr )
        {
            uint64_t data = r->data;

            if ( size == 8 )
            {
                BUILD_BUG_ON(!(PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET & 4));
                data >>= 32;
                addr += size = 4;
            }
            if ( size == 4 &&
                 ((addr & (PCI_MSIX_ENTRY_SIZE - 1)) ==
                  PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET) &&
                 !(data & PCI_MSIX_VECTOR_BITMASK) )
            {
                curr->arch.hvm_vcpu.hvm_io.msix_snoop_address = addr;
                curr->arch.hvm_vcpu.hvm_io.msix_snoop_gpa = 0;
            }
        }
        else if ( (size == 4 || size == 8) &&
                  /* Only support forward REP MOVS for now. */
                  !r->df &&
                  /*
                   * Only fully support accesses to a single table entry for
                   * now (if multiple ones get written to in one go, only the
                   * final one gets dealt with).
                   */
                  r->count && r->count <= PCI_MSIX_ENTRY_SIZE / size &&
                  !((addr + (size * r->count)) & (PCI_MSIX_ENTRY_SIZE - 1)) )
        {
            BUILD_BUG_ON((PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET + 4) &
                         (PCI_MSIX_ENTRY_SIZE - 1));

            curr->arch.hvm_vcpu.hvm_io.msix_snoop_address =
                addr + size * r->count - 4;
            curr->arch.hvm_vcpu.hvm_io.msix_snoop_gpa =
                r->data + size * r->count - 4;
        }
    }

    return 0;
}

static const struct hvm_io_ops msixtbl_mmio_ops = {
    .accept = msixtbl_range,
    .read = msixtbl_read,
    .write = _msixtbl_write,
};

static void add_msixtbl_entry(struct domain *d,
                              struct pci_dev *pdev,
                              uint64_t gtable,
                              struct msixtbl_entry *entry)
{
    INIT_LIST_HEAD(&entry->list);
    INIT_RCU_HEAD(&entry->rcu);
    atomic_set(&entry->refcnt, 0);

    entry->table_len = pdev->msix->nr_entries * PCI_MSIX_ENTRY_SIZE;
    entry->pdev = pdev;
    entry->gtable = (unsigned long) gtable;

    list_add_rcu(&entry->list, &d->arch.hvm_domain.msixtbl_list);
}

static void free_msixtbl_entry(struct rcu_head *rcu)
{
    struct msixtbl_entry *entry;

    entry = container_of (rcu, struct msixtbl_entry, rcu);

    xfree(entry);
}

static void del_msixtbl_entry(struct msixtbl_entry *entry)
{
    list_del_rcu(&entry->list);
    call_rcu(&entry->rcu, free_msixtbl_entry);
}

int msixtbl_pt_register(struct domain *d, struct pirq *pirq, uint64_t gtable)
{
    struct irq_desc *irq_desc;
    struct msi_desc *msi_desc;
    struct pci_dev *pdev;
    struct msixtbl_entry *entry, *new_entry;
    int r = -EINVAL;

    ASSERT(pcidevs_locked());
    ASSERT(spin_is_locked(&d->event_lock));

    if ( !has_vlapic(d) )
        return -ENODEV;

    /*
     * xmalloc() with irq_disabled causes the failure of check_lock() 
     * for xenpool->lock. So we allocate an entry beforehand.
     */
    new_entry = xzalloc(struct msixtbl_entry);
    if ( !new_entry )
        return -ENOMEM;

    irq_desc = pirq_spin_lock_irq_desc(pirq, NULL);
    if ( !irq_desc )
    {
        xfree(new_entry);
        return r;
    }

    msi_desc = irq_desc->msi_desc;
    if ( !msi_desc )
        goto out;

    pdev = msi_desc->dev;

    list_for_each_entry( entry, &d->arch.hvm_domain.msixtbl_list, list )
        if ( pdev == entry->pdev )
            goto found;

    entry = new_entry;
    new_entry = NULL;
    add_msixtbl_entry(d, pdev, gtable, entry);

found:
    atomic_inc(&entry->refcnt);
    r = 0;

out:
    spin_unlock_irq(&irq_desc->lock);
    xfree(new_entry);

    if ( !r )
    {
        struct vcpu *v;

        for_each_vcpu ( d, v )
        {
            if ( (v->pause_flags & VPF_blocked_in_xen) &&
                 !v->arch.hvm_vcpu.hvm_io.msix_snoop_gpa &&
                 v->arch.hvm_vcpu.hvm_io.msix_snoop_address ==
                 (gtable + msi_desc->msi_attrib.entry_nr *
                           PCI_MSIX_ENTRY_SIZE +
                  PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET) )
                v->arch.hvm_vcpu.hvm_io.msix_unmask_address =
                    v->arch.hvm_vcpu.hvm_io.msix_snoop_address;
        }
    }

    return r;
}

void msixtbl_pt_unregister(struct domain *d, struct pirq *pirq)
{
    struct irq_desc *irq_desc;
    struct msi_desc *msi_desc;
    struct pci_dev *pdev;
    struct msixtbl_entry *entry;

    ASSERT(pcidevs_locked());
    ASSERT(spin_is_locked(&d->event_lock));

    if ( !msixtbl_initialised(d) )
        return;

    irq_desc = pirq_spin_lock_irq_desc(pirq, NULL);
    if ( !irq_desc )
        return;

    msi_desc = irq_desc->msi_desc;
    if ( !msi_desc )
        goto out;

    pdev = msi_desc->dev;

    list_for_each_entry( entry, &d->arch.hvm_domain.msixtbl_list, list )
        if ( pdev == entry->pdev )
            goto found;

out:
    spin_unlock_irq(&irq_desc->lock);
    return;

found:
    if ( !atomic_dec_and_test(&entry->refcnt) )
        del_msixtbl_entry(entry);

    spin_unlock_irq(&irq_desc->lock);
}

void msixtbl_init(struct domain *d)
{
    struct hvm_io_handler *handler;

    if ( !has_hvm_container_domain(d) || !has_vlapic(d) ||
         msixtbl_initialised(d) )
        return;

    INIT_LIST_HEAD(&d->arch.hvm_domain.msixtbl_list);

    handler = hvm_next_io_handler(d);
    if ( handler )
    {
        handler->type = IOREQ_TYPE_COPY;
        handler->ops = &msixtbl_mmio_ops;
    }
}

void msixtbl_pt_cleanup(struct domain *d)
{
    struct msixtbl_entry *entry, *temp;

    if ( !msixtbl_initialised(d) )
        return;

    spin_lock(&d->event_lock);

    list_for_each_entry_safe( entry, temp,
                              &d->arch.hvm_domain.msixtbl_list, list )
        del_msixtbl_entry(entry);

    spin_unlock(&d->event_lock);
}

void msix_write_completion(struct vcpu *v)
{
    unsigned long ctrl_address = v->arch.hvm_vcpu.hvm_io.msix_unmask_address;
    unsigned long snoop_addr = v->arch.hvm_vcpu.hvm_io.msix_snoop_address;

    v->arch.hvm_vcpu.hvm_io.msix_snoop_address = 0;

    if ( !ctrl_address && snoop_addr &&
         v->arch.hvm_vcpu.hvm_io.msix_snoop_gpa )
    {
        const struct msi_desc *desc;
        uint32_t data;

        rcu_read_lock(&msixtbl_rcu_lock);
        desc = msixtbl_addr_to_desc(msixtbl_find_entry(v, snoop_addr),
                                    snoop_addr);
        rcu_read_unlock(&msixtbl_rcu_lock);

        if ( desc &&
             hvm_copy_from_guest_phys(&data,
                                      v->arch.hvm_vcpu.hvm_io.msix_snoop_gpa,
                                      sizeof(data)) == HVMCOPY_okay &&
             !(data & PCI_MSIX_VECTOR_BITMASK) )
            ctrl_address = snoop_addr;
    }

    if ( !ctrl_address )
        return;

    v->arch.hvm_vcpu.hvm_io.msix_unmask_address = 0;
    if ( msixtbl_write(v, ctrl_address, 4, 0) != X86EMUL_OKAY )
        gdprintk(XENLOG_WARNING, "MSI-X write completion failure\n");
}

/* MSI emulation. */

/* Helper to check supported MSI features. */
#define vmsi_check_type(offset, flags, what) \
        ((offset) == ((flags) & PCI_MSI_FLAGS_64BIT ? \
                      PCI_MSI_##what##_64 : PCI_MSI_##what##_32))

static inline uint64_t msi_addr64(struct hvm_pt_msi *msi)
{
    return (uint64_t)msi->addr_hi << 32 | msi->addr_lo;
}

/* Helper for updating a PIRQ-vMSI bind. */
static int vmsi_update_bind(struct hvm_pt_msi *msi)
{
    xen_domctl_bind_pt_irq_t bind;
    struct hvm_pt_device *s = container_of(msi, struct hvm_pt_device, msi);
    int rc;

    ASSERT(msi->pirq != -1);

    bind.hvm_domid = DOMID_SELF;
    bind.machine_irq = msi->pirq;
    bind.irq_type = PT_IRQ_TYPE_MSI;
    bind.u.msi.gvec = msi_vector(msi->data);
    bind.u.msi.gflags = msi_gflags(msi->data, msi_addr64(msi));
    bind.u.msi.gtable = 0;

    rc = pt_irq_create_bind(current->domain, &bind);
    if ( rc )
    {
        printk_pdev(s->pdev, XENLOG_ERR,
                      "updating of MSI failed. (err: %d)\n", rc);
        rc = physdev_unmap_pirq(DOMID_SELF, msi->pirq);
        if ( rc )
            printk_pdev(s->pdev, XENLOG_ERR,
                          "unmapping of MSI pirq %d failed. (err: %i)\n",
                          msi->pirq, rc);
        msi->pirq = -1;
        msi->mapped = false;
        msi->initialized = false;
        return rc;
    }

    return 0;
}

/* Handlers. */

/* Message Control register */
static int vmsi_msgctrl_reg_init(struct hvm_pt_device *s,
                                 struct hvm_pt_reg_handler *handler,
                                 uint32_t real_offset, uint32_t *data)
{
    struct hvm_pt_msi *msi = &s->msi;
    struct pci_dev *pdev = s->pdev;
    uint16_t reg_field;
    uint8_t seg, bus, slot, func;

    seg = pdev->seg;
    bus = pdev->bus;
    slot = PCI_SLOT(pdev->devfn);
    func = PCI_FUNC(pdev->devfn);

    /* Use I/O device register's value as initial value */
    reg_field = pci_conf_read16(seg, bus, slot, func, real_offset);
    if ( reg_field & PCI_MSI_FLAGS_ENABLE )
    {
        printk_pdev(pdev, XENLOG_INFO,
                      "MSI already enabled, disabling it first\n");
        reg_field &= ~PCI_MSI_FLAGS_ENABLE;
        pci_conf_write16(seg, bus, slot, func, real_offset, reg_field);
    }
    msi->flags |= reg_field;
    msi->ctrl_offset = real_offset;
    msi->initialized = false;
    msi->mapped = false;

    *data = handler->init_val | (reg_field & ~PCI_MSI_FLAGS_QMASK);
    return 0;
}

static int vmsi_msgctrl_reg_write(struct hvm_pt_device *s,
                                  struct hvm_pt_reg *reg, uint16_t *val,
                                  uint16_t dev_value, uint16_t valid_mask)
{
    struct hvm_pt_reg_handler *handler = reg->handler;
    struct hvm_pt_msi *msi = &s->msi;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = hvm_pt_get_throughable_mask(s, handler,
                                                            valid_mask);
    uint16_t *data = &reg->val.word;
    int rc;

    /* Currently no support for multi-vector */
    if ( *val & PCI_MSI_FLAGS_QSIZE )
        printk_pdev(s->pdev, XENLOG_WARNING,
                      "tries to set more than 1 vector ctrl %x\n", *val);

    /* Modify emulate register */
    writable_mask = handler->emu_mask & ~handler->ro_mask & valid_mask;
    *data = HVM_PT_MERGE_VALUE(*val, *data, writable_mask);
    msi->flags |= *data & ~PCI_MSI_FLAGS_ENABLE;

    /* Create value for writing to I/O device register */
    *val = HVM_PT_MERGE_VALUE(*val, dev_value, throughable_mask);

    /* update MSI */
    if ( *val & PCI_MSI_FLAGS_ENABLE )
    {
        /* Setup MSI pirq for the first time */
        if ( !msi->initialized )
        {
            struct msi_info msi_info;
            int index = -1;

            /* Init physical one */
            printk_pdev(s->pdev, XENLOG_DEBUG, "setup MSI (register: %x).\n",
                          *val);

            memset(&msi_info, 0, sizeof(msi_info));
            msi_info.seg = s->pdev->seg;
            msi_info.bus = s->pdev->bus;
            msi_info.devfn = s->pdev->devfn;

            rc = physdev_map_pirq(DOMID_SELF, MAP_PIRQ_TYPE_MSI, &index,
                                  &msi->pirq, &msi_info);
            if ( rc )
            {
                /*
                 * Do not broadcast this error, since there's nothing else
                 * that can be done (MSI setup should have been successful).
                 * Guest MSI would be actually not working.
                 */
                *val &= ~PCI_MSI_FLAGS_ENABLE;

                printk_pdev(s->pdev, XENLOG_ERR,
                              "can not map MSI (register: %x)!\n", *val);
                return 0;
            }

            rc = vmsi_update_bind(msi);
            if ( rc )
            {
                *val &= ~PCI_MSI_FLAGS_ENABLE;
                printk_pdev(s->pdev, XENLOG_ERR,
                              "can not bind MSI (register: %x)!\n", *val);
                return 0;
            }
            msi->initialized = true;
            msi->mapped = true;
        }
        msi->flags |= PCI_MSI_FLAGS_ENABLE;
    }
    else if ( msi->mapped )
    {
        uint8_t seg, bus, slot, func;
        uint8_t gvec = msi_vector(msi->data);
        uint32_t gflags = msi_gflags(msi->data, msi_addr64(msi));
        uint16_t flags;

        seg = s->pdev->seg;
        bus = s->pdev->bus;
        slot = PCI_SLOT(s->pdev->devfn);
        func = PCI_FUNC(s->pdev->devfn);

        flags = pci_conf_read16(seg, bus, slot, func, s->msi.ctrl_offset);
        pci_conf_write16(seg, bus, slot, func, s->msi.ctrl_offset,
                         flags & ~PCI_MSI_FLAGS_ENABLE);

        if ( msi->pirq == -1 )
            return 0;

        if ( msi->initialized )
        {
            xen_domctl_bind_pt_irq_t bind;

            printk_pdev(s->pdev, XENLOG_DEBUG,
                          "Unbind MSI with pirq %d, gvec %#x\n", msi->pirq,
                          gvec);

            bind.hvm_domid = DOMID_SELF;
            bind.irq_type = PT_IRQ_TYPE_MSI;
            bind.machine_irq = msi->pirq;
            bind.u.msi.gvec = gvec;
            bind.u.msi.gflags = gflags;
            bind.u.msi.gtable = 0;

            rc = pt_irq_destroy_bind(current->domain, &bind);
            if ( rc )
                printk_pdev(s->pdev, XENLOG_ERR,
                              "can not unbind MSI (register: %x)!\n", *val);

            rc = physdev_unmap_pirq(DOMID_SELF, msi->pirq);
            if ( rc )
                printk_pdev(s->pdev, XENLOG_ERR,
                              "unmapping of MSI pirq %d failed. (err: %i)\n",
                              msi->pirq, rc);
            msi->flags &= ~PCI_MSI_FLAGS_ENABLE;
            msi->initialized = false;
            msi->mapped = false;
            msi->pirq = -1;
        }
    }

    return 0;
}

/* Initialize Message Upper Address register */
static int vmsi_msgaddr64_reg_init(struct hvm_pt_device *s,
                                   struct hvm_pt_reg_handler *handler,
                                   uint32_t real_offset,
                                   uint32_t *data)
{
    /* No need to initialize in case of 32 bit type */
    if ( !(s->msi.flags & PCI_MSI_FLAGS_64BIT) )
        *data = HVM_PT_INVALID_REG;
    else
        *data = handler->init_val;

    return 0;
}

/* Write Message Address register */
static int vmsi_msgaddr32_reg_write(struct hvm_pt_device *s,
                                    struct hvm_pt_reg *reg, uint32_t *val,
                                    uint32_t dev_value, uint32_t valid_mask)
{
    struct hvm_pt_reg_handler *handler = reg->handler;
    uint32_t writable_mask = 0;
    uint32_t old_addr = reg->val.dword;
    uint32_t *data = &reg->val.dword;

    /* Modify emulate register */
    writable_mask = handler->emu_mask & ~handler->ro_mask & valid_mask;
    *data = HVM_PT_MERGE_VALUE(*val, *data, writable_mask);
    s->msi.addr_lo = *data;

    /* Create value for writing to I/O device register */
    *val = HVM_PT_MERGE_VALUE(*val, dev_value, 0);

    /* Update MSI */
    if ( *data != old_addr && s->msi.mapped )
        vmsi_update_bind(&s->msi);

    return 0;
}

/* Write Message Upper Address register */
static int vmsi_msgaddr64_reg_write(struct hvm_pt_device *s,
                                    struct hvm_pt_reg *reg, uint32_t *val,
                                    uint32_t dev_value, uint32_t valid_mask)
{
    struct hvm_pt_reg_handler *handler = reg->handler;
    uint32_t writable_mask = 0;
    uint32_t old_addr = reg->val.dword;
    uint32_t *data = &reg->val.dword;

    /* Check whether the type is 64 bit or not */
    if ( !(s->msi.flags & PCI_MSI_FLAGS_64BIT) )
    {
        printk_pdev(s->pdev, XENLOG_ERR,
                   "Can't write to the upper address without 64 bit support\n");
        return -EOPNOTSUPP;
    }

    /* Modify emulate register */
    writable_mask = handler->emu_mask & ~handler->ro_mask & valid_mask;
    *data = HVM_PT_MERGE_VALUE(*val, *data, writable_mask);
    /* update the msi_info too */
    s->msi.addr_hi = *data;

    /* Create value for writing to I/O device register */
    *val = HVM_PT_MERGE_VALUE(*val, dev_value, 0);

    /* Update MSI */
    if ( *data != old_addr && s->msi.mapped )
        vmsi_update_bind(&s->msi);

    return 0;
}

/*
 * This function is shared between 32 and 64 bits MSI implementations
 * Initialize Message Data register
 */
static int vmsi_msgdata_reg_init(struct hvm_pt_device *s,
                                 struct hvm_pt_reg_handler *handler,
                                 uint32_t real_offset,
                                 uint32_t *data)
{
    uint32_t flags = s->msi.flags;
    uint32_t offset = handler->offset;

    /* Check the offset whether matches the type or not */
    if ( vmsi_check_type(offset, flags, DATA) )
        *data = handler->init_val;
    else
        *data = HVM_PT_INVALID_REG;

    return 0;
}

/*
 * This function is shared between 32 and 64 bits MSI implementations
 * Write Message Data register
 */
static int vmsi_msgdata_reg_write(struct hvm_pt_device *s,
                                  struct hvm_pt_reg *reg, uint16_t *val,
                                  uint16_t dev_value, uint16_t valid_mask)
{
    struct hvm_pt_reg_handler *handler = reg->handler;
    struct hvm_pt_msi *msi = &s->msi;
    uint16_t writable_mask = 0;
    uint16_t old_data = reg->val.word;
    uint32_t offset = handler->offset;
    uint16_t *data = &reg->val.word;

    /* Check the offset whether matches the type or not */
    if ( !vmsi_check_type(offset, msi->flags, DATA) )
    {
        /* Exit I/O emulator */
        printk_pdev(s->pdev, XENLOG_ERR,
                      "the offset does not match the 32/64 bit type!\n");
        return -EOPNOTSUPP;
    }

    /* Modify emulate register */
    writable_mask = handler->emu_mask & ~handler->ro_mask & valid_mask;
    *data = HVM_PT_MERGE_VALUE(*val, *data, writable_mask);
    /* Update the msi_info too */
    msi->data = *data;

    /* Create value for writing to I/O device register */
    *val = HVM_PT_MERGE_VALUE(*val, dev_value, 0);

    /* Update MSI */
    if ( *data != old_data && msi->mapped )
        vmsi_update_bind(msi);

    return 0;
}

/*
 * This function is shared between 32 and 64 bits MSI implementations
 * Initialize Mask register
 */
static int vmsi_mask_reg_init(struct hvm_pt_device *s,
                              struct hvm_pt_reg_handler *handler,
                              uint32_t real_offset,
                              uint32_t *data)
{
    uint32_t flags = s->msi.flags;

    /* Check the offset whether matches the type or not */
    if ( !(flags & PCI_MSI_FLAGS_MASKBIT) )
        *data = HVM_PT_INVALID_REG;
    else if ( vmsi_check_type(handler->offset, flags, MASK) )
        *data = handler->init_val;
    else
        *data = HVM_PT_INVALID_REG;

    return 0;
}

/*
 * This function is shared between 32 and 64 bits MSI implementations
 * Initialize Pending register
 */
static int vmsi_pending_reg_init(struct hvm_pt_device *s,
                                 struct hvm_pt_reg_handler *handler,
                                 uint32_t real_offset,
                                 uint32_t *data)
{
    uint32_t flags = s->msi.flags;

    /* check the offset whether matches the type or not */
    if ( !(flags & PCI_MSI_FLAGS_MASKBIT) )
        *data = HVM_PT_INVALID_REG;
    else if ( vmsi_check_type(handler->offset, flags, PENDING) )
        *data = handler->init_val;
    else
        *data = HVM_PT_INVALID_REG;

    return 0;
}

/* MSI Capability Structure reg static information table */
static struct hvm_pt_reg_handler vmsi_handler[] = {
    /* Message Control reg */
    {
        .offset     = PCI_MSI_FLAGS,
        .size       = 2,
        .init_val   = 0x0000,
        .res_mask   = 0xFE00,
        .ro_mask    = 0x018E,
        .emu_mask   = 0x017E,
        .init       = vmsi_msgctrl_reg_init,
        .u.w.read   = hvm_pt_word_reg_read,
        .u.w.write  = vmsi_msgctrl_reg_write,
    },
    /* Message Address reg */
    {
        .offset     = PCI_MSI_ADDRESS_LO,
        .size       = 4,
        .init_val   = 0x00000000,
        .ro_mask    = 0x00000003,
        .emu_mask   = 0xFFFFFFFF,
        .init       = hvm_pt_common_reg_init,
        .u.dw.read  = hvm_pt_long_reg_read,
        .u.dw.write = vmsi_msgaddr32_reg_write,
    },
    /* Message Upper Address reg (if PCI_MSI_FLAGS_64BIT set) */
    {
        .offset     = PCI_MSI_ADDRESS_HI,
        .size       = 4,
        .init_val   = 0x00000000,
        .ro_mask    = 0x00000000,
        .emu_mask   = 0xFFFFFFFF,
        .init       = vmsi_msgaddr64_reg_init,
        .u.dw.read  = hvm_pt_long_reg_read,
        .u.dw.write = vmsi_msgaddr64_reg_write,
    },
    /* Message Data reg (16 bits of data for 32-bit devices) */
    {
        .offset     = PCI_MSI_DATA_32,
        .size       = 2,
        .init_val   = 0x0000,
        .ro_mask    = 0x0000,
        .emu_mask   = 0xFFFF,
        .init       = vmsi_msgdata_reg_init,
        .u.w.read   = hvm_pt_word_reg_read,
        .u.w.write  = vmsi_msgdata_reg_write,
    },
    /* Message Data reg (16 bits of data for 64-bit devices) */
    {
        .offset     = PCI_MSI_DATA_64,
        .size       = 2,
        .init_val   = 0x0000,
        .ro_mask    = 0x0000,
        .emu_mask   = 0xFFFF,
        .init       = vmsi_msgdata_reg_init,
        .u.w.read   = hvm_pt_word_reg_read,
        .u.w.write  = vmsi_msgdata_reg_write,
    },
    /* Mask reg (if PCI_MSI_FLAGS_MASKBIT set, for 32-bit devices) */
    {
        .offset     = PCI_MSI_DATA_64, /* PCI_MSI_MASK_32 */
        .size       = 4,
        .init_val   = 0x00000000,
        .ro_mask    = 0xFFFFFFFF,
        .emu_mask   = 0xFFFFFFFF,
        .init       = vmsi_mask_reg_init,
        .u.dw.read  = hvm_pt_long_reg_read,
        .u.dw.write = hvm_pt_long_reg_write,
    },
    /* Mask reg (if PCI_MSI_FLAGS_MASKBIT set, for 64-bit devices) */
    {
        .offset     = PCI_MSI_MASK_BIT, /* PCI_MSI_MASK_64 */
        .size       = 4,
        .init_val   = 0x00000000,
        .ro_mask    = 0xFFFFFFFF,
        .emu_mask   = 0xFFFFFFFF,
        .init       = vmsi_mask_reg_init,
        .u.dw.read  = hvm_pt_long_reg_read,
        .u.dw.write = hvm_pt_long_reg_write,
    },
    /* Pending reg (if PCI_MSI_FLAGS_MASKBIT set, for 32-bit devices) */
    {
        .offset     = PCI_MSI_DATA_64 + 4, /* PCI_MSI_PENDING_32 */
        .size       = 4,
        .init_val   = 0x00000000,
        .ro_mask    = 0xFFFFFFFF,
        .emu_mask   = 0x00000000,
        .init       = vmsi_pending_reg_init,
        .u.dw.read  = hvm_pt_long_reg_read,
        .u.dw.write = hvm_pt_long_reg_write,
    },
    /* Pending reg (if PCI_MSI_FLAGS_MASKBIT set, for 64-bit devices) */
    {
        .offset     = PCI_MSI_MASK_BIT + 4, /* PCI_MSI_PENDING_64 */
        .size       = 4,
        .init_val   = 0x00000000,
        .ro_mask    = 0xFFFFFFFF,
        .emu_mask   = 0x00000000,
        .init       = vmsi_pending_reg_init,
        .u.dw.read  = hvm_pt_long_reg_read,
        .u.dw.write = hvm_pt_long_reg_write,
    },
    /* End */
    {
        .size = 0,
    },
};

static int vmsi_group_init(struct hvm_pt_device *dev,
                                 struct hvm_pt_reg_group *group)
{
    uint8_t seg, bus, slot, func;
    struct pci_dev *pdev = dev->pdev;
    int msi_offset;
    uint8_t msi_size = 0xa;
    uint16_t flags;

    dev->msi.pirq = -1;
    seg = pdev->seg;
    bus = pdev->bus;
    slot = PCI_SLOT(pdev->devfn);
    func = PCI_FUNC(pdev->devfn);

    msi_offset = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSI);
    if ( msi_offset == 0 )
        return -ENODEV;

    group->base_offset = msi_offset;
    flags = pci_conf_read16(seg, bus, slot, func,
                            msi_offset + PCI_MSI_FLAGS);

    if ( flags & PCI_MSI_FLAGS_64BIT )
        msi_size += 4;
    if ( flags & PCI_MSI_FLAGS_MASKBIT )
        msi_size += 10;

    dev->msi.flags = flags;
    group->size = msi_size;

    return 0;
}

struct hvm_pt_handler_init hvm_pt_msi_init = {
    .handlers = vmsi_handler,
    .init = vmsi_group_init,
};

/* MSI-X */
#define latch(fld) latch[PCI_MSIX_ENTRY_##fld / sizeof(uint32_t)]

static int vmsix_update_one(struct hvm_pt_device *s, int entry_nr,
                            uint32_t vec_ctrl)
{
    struct hvm_pt_msix_entry *entry = NULL;
    xen_domctl_bind_pt_irq_t bind;
    bool bound = true;
    struct irq_desc *desc;
    unsigned long flags;
    int irq;
    int pirq;
    int rc;

    if ( entry_nr < 0 || entry_nr >= s->msix->total_entries )
        return -EINVAL;

    entry = &s->msix->msix_entry[entry_nr];

    if ( !entry->updated )
        goto mask;

    pirq = entry->pirq;

    /*
     * Update the entry addr and data to the latest values only when the
     * entry is masked or they are all masked, as required by the spec.
     * Addr and data changes while the MSI-X entry is unmasked get deferred
     * until the next masked -> unmasked transition.
     */
    if ( s->msix->maskall ||
         (entry->latch(VECTOR_CTRL_OFFSET) & PCI_MSIX_VECTOR_BITMASK) )
    {
        entry->addr = entry->latch(LOWER_ADDR_OFFSET) |
                      ((uint64_t)entry->latch(UPPER_ADDR_OFFSET) << 32);
        entry->data = entry->latch(DATA_OFFSET);
    }

    if ( pirq == -1 )
    {
        struct msi_info msi_info;
        //struct irq_desc *desc;
        int index = -1;

        /* Init physical one */
        printk_pdev(s->pdev, XENLOG_DEBUG, "setup MSI-X (entry: %d).\n",
                    entry_nr);

        memset(&msi_info, 0, sizeof(msi_info));
        msi_info.seg = s->pdev->seg;
        msi_info.bus = s->pdev->bus;
        msi_info.devfn = s->pdev->devfn;
        msi_info.table_base = s->msix->table_base;
        msi_info.entry_nr = entry_nr;

        rc = physdev_map_pirq(DOMID_SELF, MAP_PIRQ_TYPE_MSI, &index,
                              &pirq, &msi_info);
        if ( rc )
        {
            /*
             * Do not broadcast this error, since there's nothing else
             * that can be done (MSI-X setup should have been successful).
             * Guest MSI would be actually not working.
             */

            printk_pdev(s->pdev, XENLOG_ERR,
                          "can not map MSI-X (entry: %d)!\n", entry_nr);
            return rc;
        }
        entry->pirq = pirq;
        bound = false;
    }

    ASSERT(entry->pirq != -1);

    if ( bound )
    {
        printk_pdev(s->pdev, XENLOG_DEBUG, "destroy bind MSI-X entry %d\n",
                    entry_nr);
        bind.hvm_domid = DOMID_SELF;
        bind.machine_irq = entry->pirq;
        bind.irq_type = PT_IRQ_TYPE_MSI;
        bind.u.msi.gvec = msi_vector(entry->data);
        bind.u.msi.gflags = msi_gflags(entry->data, entry->addr);
        bind.u.msi.gtable = s->msix->table_base;

        pcidevs_lock();
        rc = pt_irq_destroy_bind(current->domain, &bind);
        pcidevs_unlock();
        if ( rc )
        {
            printk_pdev(s->pdev, XENLOG_ERR, "updating of MSI-X failed: %d\n",
                        rc);
            rc = physdev_unmap_pirq(DOMID_SELF, entry->pirq);
            if ( rc )
                printk_pdev(s->pdev, XENLOG_ERR,
                            "unmapping of MSI pirq %d failed: %d\n",
                            entry->pirq, rc);
            entry->pirq = -1;
            return rc;
        }
    }

    printk_pdev(s->pdev, XENLOG_DEBUG, "bind MSI-X entry %d\n", entry_nr);
    bind.hvm_domid = DOMID_SELF;
    bind.machine_irq = entry->pirq;
    bind.irq_type = PT_IRQ_TYPE_MSI;
    bind.u.msi.gvec = msi_vector(entry->data);
    bind.u.msi.gflags = msi_gflags(entry->data, entry->addr);
    bind.u.msi.gtable = s->msix->table_base;

    pcidevs_lock();
    rc = pt_irq_create_bind(current->domain, &bind);
    pcidevs_unlock();
    if ( rc )
    {
        printk_pdev(s->pdev, XENLOG_ERR, "updating of MSI-X failed: %d\n", rc);
        rc = physdev_unmap_pirq(DOMID_SELF, entry->pirq);
        if ( rc )
            printk_pdev(s->pdev, XENLOG_ERR,
                        "unmapping of MSI pirq %d failed: %d\n",
                        entry->pirq, rc);
        entry->pirq = -1;
        return rc;
    }

    entry->updated = false;

 mask:
    if ( entry->pirq != -1 &&
         ((vec_ctrl ^ entry->latch(VECTOR_CTRL_OFFSET)) &
          PCI_MSIX_VECTOR_BITMASK) )
    {
        printk_pdev(s->pdev, XENLOG_DEBUG, "%smasking MSI-X entry %d\n",
                    (vec_ctrl & PCI_MSIX_VECTOR_BITMASK) ? "" : "un", entry_nr);
        irq = domain_pirq_to_irq(s->pdev->domain, entry->pirq);
        desc = irq_to_desc(irq);
        spin_lock_irqsave(&desc->lock, flags);
        guest_mask_msi_irq(desc, !!(vec_ctrl & PCI_MSIX_VECTOR_BITMASK));
        spin_unlock_irqrestore(&desc->lock, flags);
    }

    return 0;
}

static int vmsix_update(struct hvm_pt_device *s)
{
    struct hvm_pt_msix *msix = s->msix;
    int i, rc;

    for ( i = 0; i < msix->total_entries; i++ )
    {
        rc = vmsix_update_one(s, i,
                              msix->msix_entry[i].latch(VECTOR_CTRL_OFFSET));
        if ( rc )
            printk_pdev(s->pdev, XENLOG_ERR, "failed to update MSI-X %d\n", i);
    }

    return 0;
}

static int vmsix_disable(struct hvm_pt_device *s)
{
    struct hvm_pt_msix *msix = s->msix;
    int i, rc;

    for ( i = 0; i < msix->total_entries; i++ )
    {
        struct hvm_pt_msix_entry *entry =  &s->msix->msix_entry[i];
        xen_domctl_bind_pt_irq_t bind;

        if ( entry->pirq == -1 )
            continue;

        bind.hvm_domid = DOMID_SELF;
        bind.irq_type = PT_IRQ_TYPE_MSI;
        bind.machine_irq = entry->pirq;
        bind.u.msi.gvec = msi_vector(entry->data);
        bind.u.msi.gflags = msi_gflags(entry->data, entry->addr);
        bind.u.msi.gtable = msix->table_base;
        pcidevs_lock();
        rc = pt_irq_destroy_bind(current->domain, &bind);
        pcidevs_unlock();
        if ( rc )
        {
            printk_pdev(s->pdev, XENLOG_ERR,
                        "failed to destroy MSI-X PIRQ bind entry %d: %d\n",
                        i, rc);
            return rc;
        }

        rc = physdev_unmap_pirq(DOMID_SELF, entry->pirq);
        if ( rc )
        {
            printk_pdev(s->pdev, XENLOG_ERR,
                        "failed to unmap PIRQ %d MSI-X entry %d: %d\n",
                        entry->pirq, i, rc);
            return rc;
        }

        entry->pirq = -1;
        entry->updated = false;
    }

    return 0;
}

/* Message Control register for MSI-X */
static int vmsix_ctrl_reg_init(struct hvm_pt_device *s,
                               struct hvm_pt_reg_handler *handler,
                               uint32_t real_offset, uint32_t *data)
{
    struct pci_dev *pdev = s->pdev;
    struct hvm_pt_msix *msix = s->msix;
    uint8_t seg, bus, slot, func;
    uint16_t reg_field;

    seg = pdev->seg;
    bus = pdev->bus;
    slot = PCI_SLOT(pdev->devfn);
    func = PCI_FUNC(pdev->devfn);

    /* use I/O device register's value as initial value */
    reg_field = pci_conf_read16(seg, bus, slot, func, real_offset);
    if ( reg_field & PCI_MSIX_FLAGS_ENABLE )
    {
        printk_pdev(pdev, XENLOG_INFO,
                    "MSI-X already enabled, disabling it first\n");
        reg_field &= ~PCI_MSIX_FLAGS_ENABLE;
        pci_conf_write16(seg, bus, slot, func, real_offset, reg_field);
    }

    msix->ctrl_offset = real_offset;

    *data = handler->init_val;
    return 0;
}
static int vmsix_ctrl_reg_write(struct hvm_pt_device *s, struct hvm_pt_reg *reg,
                                uint16_t *val, uint16_t dev_value,
                                uint16_t valid_mask)
{
    struct hvm_pt_reg_handler *handler = reg->handler;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = hvm_pt_get_throughable_mask(s, handler,
                                                            valid_mask);
    int debug_msix_enabled_old;
    uint16_t *data = &reg->val.word;

    /* modify emulate register */
    writable_mask = handler->emu_mask & ~handler->ro_mask & valid_mask;
    *data = HVM_PT_MERGE_VALUE(*val, *data, writable_mask);

    /* create value for writing to I/O device register */
    *val = HVM_PT_MERGE_VALUE(*val, dev_value, throughable_mask);

    /* update MSI-X */
    if ( (*val & PCI_MSIX_FLAGS_ENABLE)
         && !(*val & PCI_MSIX_FLAGS_MASKALL) )
        vmsix_update(s);
    else if ( !(*val & PCI_MSIX_FLAGS_ENABLE) && s->msix->enabled )
        vmsix_disable(s);

    s->msix->maskall = *val & PCI_MSIX_FLAGS_MASKALL;

    debug_msix_enabled_old = s->msix->enabled;
    s->msix->enabled = !!(*val & PCI_MSIX_FLAGS_ENABLE);
    if ( s->msix->enabled != debug_msix_enabled_old )
        printk_pdev(s->pdev, XENLOG_DEBUG, "%s MSI-X\n",
                    s->msix->enabled ? "enable" : "disable");

    return 0;
}

/* MSI Capability Structure reg static information table */
static struct hvm_pt_reg_handler vmsix_handler[] = {
    /* Message Control reg */
    {
        .offset     = PCI_MSIX_FLAGS,
        .size       = 2,
        .init_val   = 0x0000,
        .res_mask   = 0x3800,
        .ro_mask    = 0x07FF,
        .emu_mask   = 0x0000,
        .init       = vmsix_ctrl_reg_init,
        .u.w.read   = hvm_pt_word_reg_read,
        .u.w.write  = vmsix_ctrl_reg_write,
    },
    /* End */
    {
        .size = 0,
    },
};

static int vmsix_group_init(struct hvm_pt_device *s,
                            struct hvm_pt_reg_group *group)
{
    uint8_t seg, bus, slot, func;
    struct pci_dev *pdev = s->pdev;
    int msix_offset, total_entries, i, bar_index, rc;
    uint32_t table_off;
    uint16_t flags;

    seg = pdev->seg;
    bus = pdev->bus;
    slot = PCI_SLOT(pdev->devfn);
    func = PCI_FUNC(pdev->devfn);

    msix_offset = pci_find_cap_offset(seg, bus, slot, func, PCI_CAP_ID_MSIX);
    if ( msix_offset == 0 )
        return -ENODEV;

    group->base_offset = msix_offset;
    flags = pci_conf_read16(seg, bus, slot, func,
                            msix_offset + PCI_MSIX_FLAGS);
    total_entries = flags & PCI_MSIX_FLAGS_QSIZE;
    total_entries += 1;

    s->msix = xmalloc_bytes(sizeof(struct hvm_pt_msix) +
                            total_entries * sizeof(struct hvm_pt_msix_entry));
    if ( s->msix == NULL )
    {
        printk_pdev(pdev, XENLOG_ERR, "unable to allocate memory for MSI-X\n");
        return -ENOMEM;
    }
    memset(s->msix, 0, sizeof(struct hvm_pt_msix) +
           total_entries * sizeof(struct hvm_pt_msix_entry));

    s->msix->total_entries = total_entries;
    for ( i = 0; i < total_entries; i++ )
    {
        struct hvm_pt_msix_entry *entry = &s->msix->msix_entry[i];

        entry->pirq = -1;
        entry->latch(VECTOR_CTRL_OFFSET) = PCI_MSIX_VECTOR_BITMASK;
    }

    table_off = pci_conf_read32(seg, bus, slot, func,
                                msix_offset + PCI_MSIX_TABLE);
    bar_index = s->msix->bar_index = table_off & PCI_MSIX_BIRMASK;
    table_off &= ~PCI_MSIX_BIRMASK;
    s->msix->table_base = s->bars[bar_index].addr;
    s->msix->table_offset = table_off;
    s->msix->mmio_base_addr = s->bars[bar_index].addr + table_off;
    printk_pdev(pdev, XENLOG_DEBUG,
                "MSI-X table at BAR#%d address: %#lx size: %d\n",
                bar_index, s->msix->mmio_base_addr,
                total_entries * PCI_MSIX_ENTRY_SIZE);

    /* Unmap the BAR so that the guest cannot directly write to it. */
    rc = modify_mmio_11(s->pdev->domain, PFN_DOWN(s->msix->mmio_base_addr),
                        DIV_ROUND_UP(total_entries * PCI_MSIX_ENTRY_SIZE,
                                     PAGE_SIZE),
                        false);
    if ( rc )
    {
        printk_pdev(pdev, XENLOG_ERR,
                    "Unable to unmap address %#lx from BAR#%d\n",
                    s->bars[bar_index].addr, bar_index);
        xfree(s->msix);
        return rc;
    }

    return 0;
}

struct hvm_pt_handler_init hvm_pt_msix_init = {
    .handlers = vmsix_handler,
    .init = vmsix_group_init,
};

/* MMIO handlers for MSI-X */
static struct hvm_pt_device *vmsix_find_dev_mmio(struct domain *d,
                                                 unsigned long addr)
{
    struct hvm_pt_device *dev;

    pcidevs_lock();
    list_for_each_entry( dev, &d->arch.hvm_domain.pt_devices, entries )
    {
        unsigned long table_addr, table_size;

        if ( dev->msix == NULL )
            continue;

        table_addr = dev->msix->mmio_base_addr;
        table_size = dev->msix->total_entries * PCI_MSIX_ENTRY_SIZE;
        if ( addr < table_addr || addr >= table_addr + table_size )
            continue;

        pcidevs_unlock();
        return dev;
    }
    pcidevs_unlock();

    return NULL;
}


static uint32_t vmsix_get_entry_value(struct hvm_pt_msix_entry *e, int offset)
{
    ASSERT(!(offset % sizeof(*e->latch)));
    return e->latch[offset / sizeof(*e->latch)];
}

static void vmsix_set_entry_value(struct hvm_pt_msix_entry *e, int offset,
                                  uint32_t val)
{
    ASSERT(!(offset % sizeof(*e->latch)));
    e->latch[offset / sizeof(*e->latch)] = val;
}

static int vmsix_mem_write(struct vcpu *v, unsigned long addr,
                           unsigned int size, unsigned long val)
{
    struct hvm_pt_device *s = vmsix_find_dev_mmio(v->domain, addr);
    struct hvm_pt_msix *msix = s->msix;
    struct hvm_pt_msix_entry *entry;
    unsigned int entry_nr, offset;
    unsigned long raddr;

    raddr = addr - msix->mmio_base_addr;
    entry_nr = raddr / PCI_MSIX_ENTRY_SIZE;
    if ( entry_nr >= msix->total_entries )
    {
        printk_pdev(s->pdev, XENLOG_ERR, "asked MSI-X entry %d out of range!\n",
                    entry_nr);
        return -EINVAL;
    }

    entry = &msix->msix_entry[entry_nr];
    offset = raddr % PCI_MSIX_ENTRY_SIZE;

    if ( offset != PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET )
    {
        if ( vmsix_get_entry_value(entry, offset) == val && entry->pirq != -1 )
            return 0;

        entry->updated = true;
    }
    else
        vmsix_update_one(s, entry_nr, val);

    vmsix_set_entry_value(entry, offset, val);

    return 0;
}

static int vmsix_mem_read(struct vcpu *v, unsigned long addr,
                          unsigned int size, unsigned long *val)
{
    struct hvm_pt_device *s = vmsix_find_dev_mmio(v->domain, addr);
    struct hvm_pt_msix *msix = s->msix;
    unsigned long raddr;
    int entry_nr, offset;

    raddr = addr - msix->mmio_base_addr;
    entry_nr = raddr / PCI_MSIX_ENTRY_SIZE;
    if ( entry_nr >= msix->total_entries )
    {
        printk_pdev(s->pdev, XENLOG_ERR, "asked MSI-X entry %d out of range!\n",
                    entry_nr);
        return -EINVAL;
    }

    offset = raddr % PCI_MSIX_ENTRY_SIZE;
    *val = vmsix_get_entry_value(&msix->msix_entry[entry_nr], offset);

    return 0;
}

static int vmsix_mem_accepts(struct vcpu *v, unsigned long addr)
{
    return (vmsix_find_dev_mmio(v->domain, addr) != NULL);
}

const struct hvm_mmio_ops vmsix_mmio_ops = {
    .check = vmsix_mem_accepts,
    .read = vmsix_mem_read,
    .write = vmsix_mem_write,
};
