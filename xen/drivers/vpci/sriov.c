/*
 * Handlers for accesses to the SR-IOV capability structure.
 *
 * Copyright (C) 2018 Citrix Systems R&D
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

#include <xen/delay.h>
#include <xen/sched.h>
#include <xen/vpci.h>

#define SRIOV_SIZE(num) offsetof(struct vpci_sriov, vf[num])

static void modify_memory_mapping(const struct pci_dev *pdev, unsigned int pos,
                                  bool enable)
{
    const struct vpci_sriov *sriov = pdev->vpci->sriov;
    unsigned int i;
    int rc;

    if ( enable )
    {
        struct pci_dev *pf_dev;

        pcidevs_lock();
        /*
         * NB: a non-const pci_dev of the PF is needed in order to update
         * vf_rlen.
         */
        pf_dev = pci_get_pdev(pdev->seg, pdev->bus, pdev->devfn);
        pcidevs_unlock();
        ASSERT(pf_dev);

        /* Set the BARs addresses and size. */
        for ( i = 0; i < PCI_SRIOV_NUM_BARS; i += rc )
        {
            unsigned int j, idx = pos + PCI_SRIOV_BAR + i * 4;
            const pci_sbdf_t sbdf = {
                .sbdf = PCI_SBDF3(pdev->seg, pdev->bus, pdev->devfn),
            };
            uint32_t bar = pci_conf_read32(pdev->seg, pdev->bus,
                                           PCI_SLOT(pdev->devfn),
                                           PCI_FUNC(pdev->devfn), idx);
            uint64_t addr, size;

            rc = pci_size_mem_bar(sbdf, idx, &addr, &size,
                                  PCI_BAR_VF |
                                  ((i == PCI_SRIOV_NUM_BARS - 1) ?
                                   PCI_BAR_LAST : 0));

            /*
             * Update vf_rlen on the PF. According to the spec the size of
             * the BARs can change if the system page size register is
             * modified, so always update rlen when enabling VFs.
             */
            pf_dev->vf_rlen[i] = size;

            for ( j = 0; j < sriov->num_vfs; j++ )
            {
                struct vpci_header *header;

                if ( !sriov->vf[j] )
                    /* Can happen if pci_add_device fails. */
                    continue;

                spin_lock(&sriov->vf[j]->vpci_lock);
                header = &sriov->vf[j]->vpci->header;

                if ( !size )
                {
                    header->bars[i].type = VPCI_BAR_EMPTY;
                    spin_unlock(&sriov->vf[j]->vpci_lock);
                    continue;
                }

                header->bars[i].addr = addr + size * j;
                header->bars[i].size = size;
                header->bars[i].prefetchable =
                    bar & PCI_BASE_ADDRESS_MEM_PREFETCH;

                switch ( rc )
                {
                case 1:
                    header->bars[i].type = VPCI_BAR_MEM32;
                    break;

                case 2:
                    header->bars[i].type = VPCI_BAR_MEM64_LO;
                    header->bars[i + 1].type = VPCI_BAR_MEM64_HI;
                    break;

                default:
                    ASSERT_UNREACHABLE();
                    spin_unlock(&sriov->vf[j]->vpci_lock);
                    domain_crash(pdev->domain);
                    return;
                }
                spin_unlock(&sriov->vf[j]->vpci_lock);
            }
        }
    }

    /* Add/remove mappings for the VFs BARs into the p2m. */
    for ( i = 0; i < sriov->num_vfs; i++ )
    {
        struct pci_dev *vf_pdev = sriov->vf[i];

        spin_lock(&vf_pdev->vpci_lock);
        rc = vpci_modify_bars(vf_pdev, enable, false);
        spin_unlock(&vf_pdev->vpci_lock);
        if ( rc )
            gprintk(XENLOG_ERR,
                    "failed to %smap BARs of VF %04x:%02x:%02x.%u: %d\n",
                    enable ? "" : "un", vf_pdev->seg, vf_pdev->bus,
                    PCI_SLOT(vf_pdev->devfn), PCI_FUNC(vf_pdev->devfn), rc);
    }
}

static void enable_tail(const struct pci_dev *pdev, struct vpci_sriov *sriov,
                        unsigned int pos, bool new_enabled,
                        bool new_mem_enabled)
{
    uint16_t offset = pci_conf_read16(pdev->seg, pdev->bus,
                                      PCI_SLOT(pdev->devfn),
                                      PCI_FUNC(pdev->devfn),
                                      pos + PCI_SRIOV_VF_OFFSET);
    uint16_t stride = pci_conf_read16(pdev->seg, pdev->bus,
                                      PCI_SLOT(pdev->devfn),
                                      PCI_FUNC(pdev->devfn),
                                      pos + PCI_SRIOV_VF_STRIDE);
    unsigned int i;

    for ( i = 0; i < sriov->num_vfs; i++ )
    {
        const pci_sbdf_t bdf = {
            .bdf = PCI_BDF2(pdev->bus, pdev->devfn) + offset + stride * i,
        };
        int rc;

        if ( new_enabled )
        {
            const struct pci_dev_info info = {
                .is_virtfn = true,
                .physfn.bus = pdev->bus,
                .physfn.devfn = pdev->devfn,
            };

            rc = pci_add_device(pdev->seg, bdf.bus, bdf.extfunc, &info,
                                pdev->node);
        }
        else
            rc = pci_remove_device(pdev->seg, bdf.bus, bdf.extfunc);
        if ( rc )
            gprintk(XENLOG_ERR, "failed to %s VF %04x:%02x:%02x.%u: %d\n",
                    new_enabled ? "add" : "remove", pdev->seg, bdf.bus,
                    bdf.dev, bdf.func, rc);

        pcidevs_lock();
        sriov->vf[i] = pci_get_pdev(pdev->seg, bdf.bus, bdf.extfunc);
        pcidevs_unlock();
    }

    if ( new_mem_enabled )
        modify_memory_mapping(pdev, pos, true);
}

struct callback_data {
    const struct pci_dev *pdev;
    struct vpci_sriov *sriov;
    unsigned int pos;
    uint32_t value;
    bool new_enabled;
    bool new_mem_enabled;
};

static void enable_callback(void *data)
{
    struct callback_data *cb = data;
    const struct pci_dev *pdev = cb->pdev;

    enable_tail(pdev, cb->sriov, cb->pos, cb->new_enabled,
                cb->new_mem_enabled);
    pci_conf_write16(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                     PCI_FUNC(pdev->devfn), cb->pos + PCI_SRIOV_CTRL,
                     cb->value);
    xfree(cb);
}

static void control_write(const struct pci_dev *pdev, unsigned int reg,
                          uint32_t val, void *data)
{
    struct vpci_sriov *sriov = data;
    unsigned int pos = reg - PCI_SRIOV_CTRL;
    uint16_t control = pci_conf_read16(pdev->seg, pdev->bus,
                                       PCI_SLOT(pdev->devfn),
                                       PCI_FUNC(pdev->devfn),
                                       pos + PCI_SRIOV_CTRL);
    bool enabled = control & PCI_SRIOV_CTRL_VFE;
    bool mem_enabled = control & PCI_SRIOV_CTRL_MSE;
    bool new_enabled = val & PCI_SRIOV_CTRL_VFE;
    bool new_mem_enabled = val & PCI_SRIOV_CTRL_MSE;

    if ( new_enabled != enabled )
    {
        if ( new_enabled )
        {
            struct callback_data *cb = xmalloc(struct callback_data);
            struct vcpu *curr = current;

            if ( !cb )
            {
                gprintk(XENLOG_WARNING, "%04x:%02x:%02x.%u: "
                        "unable to allocate memory for SR-IOV enable\n",
                        pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                        PCI_FUNC(pdev->devfn));
                return;
            }

            /*
             * Only update the number of active VFs when enabling, when
             * disabling use the cached value in order to always remove the
             * same number of VFs that were active.
             */
            sriov->num_vfs = pci_conf_read16(pdev->seg, pdev->bus,
                                             PCI_SLOT(pdev->devfn),
                                             PCI_FUNC(pdev->devfn),
                                             pos + PCI_SRIOV_NUM_VF);

            /*
             * NB: VFE needs to be enabled before calling pci_add_device so Xen
             * can access the config space of VFs.
             */
            pci_conf_write16(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                             PCI_FUNC(pdev->devfn), reg,
                             control | PCI_SRIOV_CTRL_VFE);

            /*
             * The spec states that the software must wait at least 100ms
             * before attempting to access VF registers when enabling virtual
             * functions on the PF.
             */
            cb->pdev = pdev;
            cb->sriov = sriov;
            cb->pos = pos;
            cb->value = val;
            cb->new_enabled = new_enabled;
            cb->new_mem_enabled = new_mem_enabled;
            curr->vpci.task = WAIT;
            curr->vpci.wait.callback = enable_callback;
            curr->vpci.wait.data = cb;
            curr->vpci.wait.end = get_cycles() + 100 * cpu_khz;
            return;
        }

        enable_tail(pdev, sriov, pos, new_enabled, new_mem_enabled);
    }
    else if ( new_mem_enabled != mem_enabled && new_enabled )
        modify_memory_mapping(pdev, pos, new_mem_enabled);

    pci_conf_write16(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                     PCI_FUNC(pdev->devfn), reg, val);
}

static int init_sriov(struct pci_dev *pdev)
{
    unsigned int pos = pci_find_ext_capability(pdev->seg, pdev->bus,
                                               pdev->devfn,
                                               PCI_EXT_CAP_ID_SRIOV);
    uint16_t total_vfs;

    if ( !pos )
        return 0;

    total_vfs = pci_conf_read16(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                                PCI_FUNC(pdev->devfn),
                                pos + PCI_SRIOV_TOTAL_VF);

    pdev->vpci->sriov = xzalloc_bytes(SRIOV_SIZE(total_vfs));
    if ( !pdev->vpci->sriov )
        return -ENOMEM;

    return vpci_add_register(pdev->vpci, vpci_hw_read16, control_write,
                             pos + PCI_SRIOV_CTRL, 2, pdev->vpci->sriov);
}

static void teardown_sriov(struct pci_dev *pdev)
{
    if ( pdev->vpci->sriov )
    {
        /* TODO: removing PFs is not currently supported. */
        ASSERT_UNREACHABLE();
        xfree(pdev->vpci->sriov);
        domain_crash(pdev->domain);
    }
}
REGISTER_VPCI_INIT(init_sriov, teardown_sriov, VPCI_PRIORITY_LOW);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
