/*
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2006, Keir Fraser, XenSource Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License, version 
 * 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT ANY 
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS 
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more 
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>

#include "acpi2_0.h"
#include "ssdt_s3.h"
#include "ssdt_s4.h"
#include "ssdt_tpm.h"
#include "ssdt_pm.h"
#include "x86.h"
#include <xen/hvm/hvm_info_table.h>
#include <xen/hvm/hvm_xs_strings.h>
#include <xen/hvm/params.h>

#define ACPI_MAX_SECONDARY_TABLES 16

#define align16(sz)        (((sz) + 15) & ~15)
#define fixed_strcpy(d, s) strncpy((d), (s), sizeof(d))
#ifndef offsetof
#define offsetof(t, m) ((unsigned long)&((t *)0)->m)
#endif
#ifndef NULL
#define NULL ((void *)0)
#endif

extern struct acpi_20_rsdp Rsdp;
extern struct acpi_20_rsdt Rsdt;
extern struct acpi_20_xsdt Xsdt;
extern struct acpi_20_fadt Fadt;
extern struct acpi_20_facs Facs;
extern struct acpi_20_waet Waet;

/* Number of processor objects in the chosen DSDT. */
static unsigned int nr_processor_objects;

static inline int __test_bit(unsigned int b, void *p)
{
    return !!(((uint8_t *)p)[b>>3] & (1u<<(b&7)));
}

static void set_checksum(
    void *table, uint32_t checksum_offset, uint32_t length)
{
    uint8_t *p, sum = 0;

    p = table;
    p[checksum_offset] = 0;

    while ( length-- )
        sum = sum + *p++;

    p = table;
    p[checksum_offset] = -sum;
}

static struct acpi_20_madt *construct_madt(struct acpi_config *config)
{
    struct acpi_20_madt           *madt;
    struct acpi_20_madt_intsrcovr *intsrcovr;
    struct acpi_20_madt_ioapic    *io_apic;
    struct acpi_20_madt_lapic     *lapic;
    int i, sz;

    sz  = sizeof(struct acpi_20_madt);
    sz += sizeof(struct acpi_20_madt_intsrcovr) * 16;
    sz += sizeof(struct acpi_20_madt_ioapic);
    sz += sizeof(struct acpi_20_madt_lapic) * nr_processor_objects;

    madt = config->mem_ops.alloc(sz, 16);
    if (!madt) return NULL;

    memset(madt, 0, sizeof(*madt));
    madt->header.signature    = ACPI_2_0_MADT_SIGNATURE;
    madt->header.revision     = ACPI_2_0_MADT_REVISION;
    fixed_strcpy(madt->header.oem_id, ACPI_OEM_ID);
    fixed_strcpy(madt->header.oem_table_id, ACPI_OEM_TABLE_ID);
    madt->header.oem_revision = ACPI_OEM_REVISION;
    madt->header.creator_id   = ACPI_CREATOR_ID;
    madt->header.creator_revision = ACPI_CREATOR_REVISION;
    madt->lapic_addr = LAPIC_BASE_ADDRESS;
    madt->flags      = ACPI_PCAT_COMPAT;

    if ( config->table_flags & ACPI_BUILD_IOAPIC )
    {
        intsrcovr = (struct acpi_20_madt_intsrcovr *)(madt + 1);
        for ( i = 0; i < 16; i++ )
        {
            memset(intsrcovr, 0, sizeof(*intsrcovr));
            intsrcovr->type   = ACPI_INTERRUPT_SOURCE_OVERRIDE;
            intsrcovr->length = sizeof(*intsrcovr);
            intsrcovr->source = i;

            if ( i == 0 )
            {
                /* ISA IRQ0 routed to IOAPIC GSI 2. */
                intsrcovr->gsi    = 2;
                intsrcovr->flags  = 0x0;
            }
            else if ( PCI_ISA_IRQ_MASK & (1U << i) )
            {
                /* PCI: active-low level-triggered. */
                intsrcovr->gsi    = i;
                intsrcovr->flags  = 0xf;
            }
            else
            {
                /* No need for a INT source override structure. */
                continue;
            }

            intsrcovr++;
        }

        io_apic = (struct acpi_20_madt_ioapic *)intsrcovr;
        memset(io_apic, 0, sizeof(*io_apic));
        io_apic->type        = ACPI_IO_APIC;
        io_apic->length      = sizeof(*io_apic);
        io_apic->ioapic_id   = IOAPIC_ID;
        io_apic->ioapic_addr = IOAPIC_BASE_ADDRESS;

        lapic = (struct acpi_20_madt_lapic *)(io_apic + 1);
    }
    else
        lapic = (struct acpi_20_madt_lapic *)(madt + 1);

    config->acpi_info.madt_lapic0_addr = config->mem_ops.v2p(lapic);
    for ( i = 0; i < nr_processor_objects; i++ )
    {
        memset(lapic, 0, sizeof(*lapic));
        lapic->type    = ACPI_PROCESSOR_LOCAL_APIC;
        lapic->length  = sizeof(*lapic);
        /* Processor ID must match processor-object IDs in the DSDT. */
        lapic->acpi_processor_id = i;
        lapic->apic_id = LAPIC_ID(i);
        lapic->flags = ((i < config->nr_vcpus) &&
                        __test_bit(i, config->vcpu_online)
                        ? ACPI_LOCAL_APIC_ENABLED : 0);
        lapic++;
    }

    madt->header.length = (unsigned char *)lapic - (unsigned char *)madt;
    set_checksum(madt, offsetof(struct acpi_header, checksum),
                 madt->header.length);
    config->acpi_info.madt_csum_addr =
        config->mem_ops.v2p(&madt->header.checksum);

    return madt;
}

static struct acpi_20_hpet *construct_hpet(struct acpi_config *config)
{
    struct acpi_20_hpet *hpet;

    hpet = config->mem_ops.alloc(sizeof(*hpet), 16);
    if (!hpet) return NULL;

    memset(hpet, 0, sizeof(*hpet));
    hpet->header.signature    = ACPI_2_0_HPET_SIGNATURE;
    hpet->header.revision     = ACPI_2_0_HPET_REVISION;
    fixed_strcpy(hpet->header.oem_id, ACPI_OEM_ID);
    fixed_strcpy(hpet->header.oem_table_id, ACPI_OEM_TABLE_ID);
    hpet->header.oem_revision = ACPI_OEM_REVISION;
    hpet->header.creator_id   = ACPI_CREATOR_ID;
    hpet->header.creator_revision = ACPI_CREATOR_REVISION;
    hpet->timer_block_id      = 0x8086a201;
    hpet->addr.address        = ACPI_HPET_ADDRESS;

    hpet->header.length = sizeof(*hpet);
    set_checksum(hpet, offsetof(struct acpi_header, checksum), sizeof(*hpet));
    return hpet;
}

static struct acpi_20_waet *construct_waet(struct acpi_config *config)
{
    struct acpi_20_waet *waet;

    waet = config->mem_ops.alloc(sizeof(*waet), 16);
    if (!waet) return NULL;

    memcpy(waet, &Waet, sizeof(*waet));

    waet->header.length = sizeof(*waet);
    set_checksum(waet, offsetof(struct acpi_header, checksum), sizeof(*waet));

    return waet;
}

static struct acpi_20_srat *construct_srat(struct acpi_config *config)
{
    struct acpi_20_srat *srat;
    struct acpi_20_srat_processor *processor;
    struct acpi_20_srat_memory *memory;
    unsigned int size;
    void *p;
    unsigned int i;

    size = sizeof(*srat) + sizeof(*processor) * config->nr_vcpus +
           sizeof(*memory) * config->numa.nr_vmemranges;

    p = config->mem_ops.alloc(size, 16);
    if ( !p )
        return NULL;

    srat = memset(p, 0, size);
    srat->header.signature    = ACPI_2_0_SRAT_SIGNATURE;
    srat->header.revision     = ACPI_2_0_SRAT_REVISION;
    fixed_strcpy(srat->header.oem_id, ACPI_OEM_ID);
    fixed_strcpy(srat->header.oem_table_id, ACPI_OEM_TABLE_ID);
    srat->header.oem_revision = ACPI_OEM_REVISION;
    srat->header.creator_id   = ACPI_CREATOR_ID;
    srat->header.creator_revision = ACPI_CREATOR_REVISION;
    srat->table_revision      = ACPI_SRAT_TABLE_REVISION;

    processor = (struct acpi_20_srat_processor *)(srat + 1);
    for ( i = 0; i < config->nr_vcpus; i++ )
    {
        processor->type     = ACPI_PROCESSOR_AFFINITY;
        processor->length   = sizeof(*processor);
        processor->domain   = config->numa.vcpu_to_vnode[i];
        processor->apic_id  = LAPIC_ID(i);
        processor->flags    = ACPI_LOCAL_APIC_AFFIN_ENABLED;
        processor++;
    }

    memory = (struct acpi_20_srat_memory *)processor;
    for ( i = 0; i < config->numa.nr_vmemranges; i++ )
    {
        memory->type          = ACPI_MEMORY_AFFINITY;
        memory->length        = sizeof(*memory);
        memory->domain        = config->numa.vmemrange[i].nid;
        memory->flags         = ACPI_MEM_AFFIN_ENABLED;
        memory->base_address  = config->numa.vmemrange[i].start;
        memory->mem_length    = config->numa.vmemrange[i].end -
            config->numa.vmemrange[i].start;
        memory++;
    }

    srat->header.length = size;
    set_checksum(srat, offsetof(struct acpi_header, checksum), size);

    return srat;
}

static struct acpi_20_slit *construct_slit(struct acpi_config *config)
{
    struct acpi_20_slit *slit;
    unsigned int i, num, size;

    num = config->numa.nr_vnodes * config->numa.nr_vnodes;
    size = sizeof(*slit) + num * sizeof(uint8_t);

    slit = config->mem_ops.alloc(size, 16);
    if ( !slit )
        return NULL;

    memset(slit, 0, size);
    slit->header.signature    = ACPI_2_0_SLIT_SIGNATURE;
    slit->header.revision     = ACPI_2_0_SLIT_REVISION;
    fixed_strcpy(slit->header.oem_id, ACPI_OEM_ID);
    fixed_strcpy(slit->header.oem_table_id, ACPI_OEM_TABLE_ID);
    slit->header.oem_revision = ACPI_OEM_REVISION;
    slit->header.creator_id   = ACPI_CREATOR_ID;
    slit->header.creator_revision = ACPI_CREATOR_REVISION;

    for ( i = 0; i < num; i++ )
        slit->entry[i] = config->numa.vdistance[i];

    slit->localities = config->numa.nr_vnodes;

    slit->header.length = size;
    set_checksum(slit, offsetof(struct acpi_header, checksum), size);

    return slit;
}

static int construct_passthrough_tables(unsigned long *table_ptrs,
                                        int nr_tables,
                                        struct acpi_config *config)
{
    unsigned long acpi_pt_addr;
    uint32_t acpi_pt_length;
    struct acpi_header *header;
    int nr_added;
    int nr_max = (ACPI_MAX_SECONDARY_TABLES - nr_tables - 1);
    uint32_t total = 0;
    uint8_t *buffer;

    if ( config->pt.acpi_pt_addr == 0 )
        return 0;

    acpi_pt_addr = config->pt.acpi_pt_addr;
    acpi_pt_length = config->pt.acpi_pt_length;

    for ( nr_added = 0; nr_added < nr_max; nr_added++ )
    {        
        if ( (acpi_pt_length - total) < sizeof(struct acpi_header) )
            break;

        header = (struct acpi_header*)acpi_pt_addr;

        buffer = config->mem_ops.alloc(header->length, 16);
        if ( buffer == NULL )
            break;
        memcpy(buffer, header, header->length);

        table_ptrs[nr_tables++] = config->mem_ops.v2p(buffer);
        total += header->length;
        acpi_pt_addr += header->length;
    }

    return nr_added;
}

static int construct_secondary_tables(unsigned long *table_ptrs,
                                      struct acpi_config *config)
{
    int nr_tables = 0;
    struct acpi_20_madt *madt;
    struct acpi_20_hpet *hpet;
    struct acpi_20_waet *waet;
    struct acpi_20_tcpa *tcpa;
    unsigned char *ssdt;
    static const uint16_t tis_signature[] = {0x0001, 0x0001, 0x0001};
    void *lasa;

    /* MADT. */
    if ( (config->nr_vcpus > 1) || config->apic_mode )
    {
        madt = construct_madt(config);
        if (!madt) return -1;
        table_ptrs[nr_tables++] = config->mem_ops.v2p(madt);
    }

    /* HPET. */
    if ( config->acpi_info.hpet_present )
    {
        hpet = construct_hpet(config);
        if (!hpet) return -1;
        table_ptrs[nr_tables++] = config->mem_ops.v2p(hpet);
    }

    /* WAET. */
    if ( config->table_flags & ACPI_BUILD_WAET )
    {
        waet = construct_waet(config);
        if (!waet) return -1;
        table_ptrs[nr_tables++] = config->mem_ops.v2p(waet);
    }

    if ( config->table_flags & ACPI_BUILD_SSDT_PM )
    {
        ssdt = config->mem_ops.alloc(sizeof(ssdt_pm), 16);
        if (!ssdt) return -1;
        memcpy(ssdt, ssdt_pm, sizeof(ssdt_pm));
        table_ptrs[nr_tables++] = config->mem_ops.v2p(ssdt);
    }

    if ( config->table_flags & ACPI_BUILD_SSDT_S3 )
    {
        ssdt = config->mem_ops.alloc(sizeof(ssdt_s3), 16);
        if (!ssdt) return -1;
        memcpy(ssdt, ssdt_s3, sizeof(ssdt_s3));
        table_ptrs[nr_tables++] = config->mem_ops.v2p(ssdt);
    } else {
        printf("S3 disabled\n");
    }

    if ( config->table_flags & ACPI_BUILD_SSDT_S4 )
    {
        ssdt = config->mem_ops.alloc(sizeof(ssdt_s4), 16);
        if (!ssdt) return -1;
        memcpy(ssdt, ssdt_s4, sizeof(ssdt_s4));
        table_ptrs[nr_tables++] = config->mem_ops.v2p(ssdt);
    } else {
        printf("S4 disabled\n");
    }

    if ( config->table_flags & ACPI_BUILD_TCPA )
    {
        /* TPM TCPA and SSDT. */
        if ( (config->tis_hdr[0] == tis_signature[0]) &&
             (config->tis_hdr[1] == tis_signature[1]) &&
             (config->tis_hdr[2] == tis_signature[2]) )
        {
            ssdt = config->mem_ops.alloc(sizeof(ssdt_tpm), 16);
            if (!ssdt) return -1;
            memcpy(ssdt, ssdt_tpm, sizeof(ssdt_tpm));
            table_ptrs[nr_tables++] = config->mem_ops.v2p(ssdt);

            tcpa = config->mem_ops.alloc(sizeof(struct acpi_20_tcpa), 16);
            if (!tcpa) return -1;
            memset(tcpa, 0, sizeof(*tcpa));
            table_ptrs[nr_tables++] = config->mem_ops.v2p(tcpa);

            tcpa->header.signature = ACPI_2_0_TCPA_SIGNATURE;
            tcpa->header.length    = sizeof(*tcpa);
            tcpa->header.revision  = ACPI_2_0_TCPA_REVISION;
            fixed_strcpy(tcpa->header.oem_id, ACPI_OEM_ID);
            fixed_strcpy(tcpa->header.oem_table_id, ACPI_OEM_TABLE_ID);
            tcpa->header.oem_revision = ACPI_OEM_REVISION;
            tcpa->header.creator_id   = ACPI_CREATOR_ID;
            tcpa->header.creator_revision = ACPI_CREATOR_REVISION;
            if ( (lasa = config->mem_ops.alloc(ACPI_2_0_TCPA_LAML_SIZE, 16)) != NULL )
            {
                tcpa->lasa = config->mem_ops.v2p(lasa);
                tcpa->laml = ACPI_2_0_TCPA_LAML_SIZE;
                memset(lasa, 0, tcpa->laml);
                set_checksum(tcpa,
                             offsetof(struct acpi_header, checksum),
                             tcpa->header.length);
            }
        }
    }
    
    /* SRAT and SLIT */
    if ( config->numa.nr_vnodes > 0 )
    {
        struct acpi_20_srat *srat = construct_srat(config);
        struct acpi_20_slit *slit = construct_slit(config);

        if ( srat )
            table_ptrs[nr_tables++] = config->mem_ops.v2p(srat);
        else
            printf("Failed to build SRAT, skipping...\n");
        if ( slit )
            table_ptrs[nr_tables++] = config->mem_ops.v2p(slit);
        else
            printf("Failed to build SLIT, skipping...\n");
    }

    /* Load any additional tables passed through. */
    nr_tables += construct_passthrough_tables(table_ptrs, nr_tables, config);

    table_ptrs[nr_tables] = 0;
    return nr_tables;
}

/**
 * Allocate and initialize Windows Generation ID
 * If value is not present in the XenStore or if all zeroes
 * the device will be not active
 *
 * Return 0 if memory failure, != 0 if success
 */
static int new_vm_gid(struct acpi_config *config)
{
    uint64_t *buf;

    config->acpi_info.vm_gid_addr = 0;

    /* check for 0 ID*/
    if ( !config->vm_gid[0] && !config->vm_gid[1] )
        return 1;

    /* copy to allocate BIOS memory */
    buf = (uint64_t *) config->mem_ops.alloc(sizeof(config->vm_gid), 8);
    if ( !buf )
        return 0;
    memcpy(buf, config->vm_gid, sizeof(config->vm_gid));

    /* set into ACPI table and HVM param the address */
    config->acpi_info.vm_gid_addr = config->mem_ops.v2p(buf);

    return 1;
}

void acpi_build_tables(struct acpi_config *config, unsigned long physical)
{
    struct acpi_20_rsdp *rsdp;
    struct acpi_20_rsdt *rsdt;
    struct acpi_20_xsdt *xsdt;
    struct acpi_20_fadt *fadt;
    struct acpi_10_fadt *fadt_10;
    struct acpi_20_facs *facs;
    unsigned char       *dsdt;
    unsigned long        secondary_tables[ACPI_MAX_SECONDARY_TABLES];
    int                  nr_secondaries, i;

    if ( !config->mem_ops.alloc || !config->mem_ops.v2p )
    {
        printf("unable to build ACPI tables: no memory ops\n");
        return;
    }

    /*
     * Fill in high-memory data structures, starting at @buf.
     */

    facs = config->mem_ops.alloc(sizeof(struct acpi_20_facs), 16);
    if (!facs) goto oom;
    memcpy(facs, &Facs, sizeof(struct acpi_20_facs));

    /*
     * Alternative DSDTs we get linked against. A cover-all DSDT for up to the
     * implementation-defined maximum number of VCPUs, and an alternative for use
     * when a guest can only have up to 15 VCPUs.
     *
     * The latter is required for Windows 2000, which experiences a BSOD of
     * KMODE_EXCEPTION_NOT_HANDLED if it sees more than 15 processor objects.
     */
    if ( config->nr_vcpus <= 15 && config->dsdt_15cpu)
    {
        dsdt = config->mem_ops.alloc(config->dsdt_15cpu_len, 16);
        if (!dsdt) goto oom;
        memcpy(dsdt, config->dsdt_15cpu, config->dsdt_15cpu_len);
        nr_processor_objects = 15;
    }
    else
    {
        dsdt = config->mem_ops.alloc(config->dsdt_anycpu_len, 16);
        if (!dsdt) goto oom;
        memcpy(dsdt, config->dsdt_anycpu, config->dsdt_anycpu_len);
        nr_processor_objects = HVM_MAX_VCPUS;
    }

    /*
     * N.B. ACPI 1.0 operating systems may not handle FADT with revision 2
     * or above properly, notably Windows 2000, which tries to copy FADT
     * into a 116 bytes buffer thus causing an overflow. The solution is to
     * link the higher revision FADT with the XSDT only and introduce a
     * compatible revision 1 FADT that is linked with the RSDT. Refer to:
     *     http://www.acpi.info/presentations/S01USMOBS169_OS%20new.ppt
     */
    fadt_10 = config->mem_ops.alloc(sizeof(struct acpi_10_fadt), 16);
    if (!fadt_10) goto oom;
    memcpy(fadt_10, &Fadt, sizeof(struct acpi_10_fadt));
    fadt_10->header.length = sizeof(struct acpi_10_fadt);
    fadt_10->header.revision = ACPI_1_0_FADT_REVISION;
    fadt_10->dsdt          = config->mem_ops.v2p(dsdt);
    fadt_10->firmware_ctrl = config->mem_ops.v2p(facs);
    set_checksum(fadt_10,
                 offsetof(struct acpi_header, checksum),
                 sizeof(struct acpi_10_fadt));

    fadt = config->mem_ops.alloc(sizeof(struct acpi_20_fadt), 16);
    if (!fadt) goto oom;
    memcpy(fadt, &Fadt, sizeof(struct acpi_20_fadt));
    fadt->dsdt   = config->mem_ops.v2p(dsdt);
    fadt->x_dsdt = config->mem_ops.v2p(dsdt);
    fadt->firmware_ctrl   = config->mem_ops.v2p(facs);
    fadt->x_firmware_ctrl = config->mem_ops.v2p(facs);
    set_checksum(fadt,
                 offsetof(struct acpi_header, checksum),
                 sizeof(struct acpi_20_fadt));

    nr_secondaries = construct_secondary_tables(secondary_tables, config);
    if ( nr_secondaries < 0 )
        goto oom;

    xsdt = config->mem_ops.alloc(sizeof(struct acpi_20_xsdt)+
                     sizeof(uint64_t)*nr_secondaries,
                     16);
    if (!xsdt) goto oom;
    memcpy(xsdt, &Xsdt, sizeof(struct acpi_header));
    xsdt->entry[0] = config->mem_ops.v2p(fadt);
    for ( i = 0; secondary_tables[i]; i++ )
        xsdt->entry[i+1] = secondary_tables[i];
    xsdt->header.length = sizeof(struct acpi_header) + (i+1)*sizeof(uint64_t);
    set_checksum(xsdt,
                 offsetof(struct acpi_header, checksum),
                 xsdt->header.length);

    rsdt = config->mem_ops.alloc(sizeof(struct acpi_20_rsdt)+
                     sizeof(uint32_t)*nr_secondaries,
                     16);
    if (!rsdt) goto oom;
    memcpy(rsdt, &Rsdt, sizeof(struct acpi_header));
    rsdt->entry[0] = config->mem_ops.v2p(fadt_10);
    for ( i = 0; secondary_tables[i]; i++ )
        rsdt->entry[i+1] = secondary_tables[i];
    rsdt->header.length = sizeof(struct acpi_header) + (i+1)*sizeof(uint32_t);
    set_checksum(rsdt,
                 offsetof(struct acpi_header, checksum),
                 rsdt->header.length);

    /*
     * Fill in low-memory data structures: acpi_info and RSDP.
     */
    rsdp = (struct acpi_20_rsdp *)physical;

    memcpy(rsdp, &Rsdp, sizeof(struct acpi_20_rsdp));
    rsdp->rsdt_address = config->mem_ops.v2p(rsdt);
    rsdp->xsdt_address = config->mem_ops.v2p(xsdt);
    set_checksum(rsdp,
                 offsetof(struct acpi_10_rsdp, checksum),
                 sizeof(struct acpi_10_rsdp));
    set_checksum(rsdp,
                 offsetof(struct acpi_20_rsdp, extended_checksum),
                 sizeof(struct acpi_20_rsdp));

    if ( !new_vm_gid(config) )
        goto oom;

    memcpy(config->acpi_info_page, &config->acpi_info,
           sizeof(config->acpi_info));

    return;

oom:
    printf("unable to build ACPI tables: out of memory\n");

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
