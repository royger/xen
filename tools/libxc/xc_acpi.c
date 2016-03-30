#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include <xen/xen.h>
#include <xen/foreign/x86_32.h>
#include <xen/foreign/x86_64.h>
#include <xen/hvm/hvm_info_table.h>
#include <xen/io/protocols.h>

#include "xg_private.h"
#include "xc_dom.h"
#include "xenctrl.h"

#include "acpi2_0.h"

#define RESERVED_MEMORY_DYNAMIC_START 0xFC001000
#define ACPI_PHYSICAL_ADDRESS         0x000EA020

/* Initial allocation for ACPI tables */
#define NUM_ACPI_PAGES  16

#define PFN(paddr)  ((paddr) >> PAGE_SHIFT)

extern unsigned char dsdt_anycpu[], dsdt_15cpu[], dsdt_empty[];
extern int dsdt_anycpu_len, dsdt_15cpu_len, dsdt_empty_len;

static uint64_t alloc_up, alloc_down;
static unsigned long base_addr;

/* Assumes contiguous physical space */
static unsigned long virt_to_phys(void *v)
{
	return (((unsigned long)v - base_addr) + RESERVED_MEMORY_DYNAMIC_START);
}

static void *mem_alloc(uint32_t size, uint32_t align)
{
    uint64_t s, e;

    /* Align to at least 16 bytes. */
    if ( align < 16 )
        align = 16;

    s = (alloc_up + align) & ~((uint64_t)align - 1);
    e = s + size - 1;

    /* TODO: Reallocate memory */
    if ((e < s) || (e >= alloc_down)) return NULL;

    while ( PFN(alloc_up) != PFN(e) )
    {
        alloc_up += PAGE_SIZE;
    }

    alloc_up = e;

    return (void *)(unsigned long)s;
}

static int init_acpi_config(struct xc_dom_image *dom,
                            struct acpi_config *config)
{
    xc_interface *xch = dom->xch;
    uint32_t domid = dom->guest_domid;
    xc_dominfo_t info;
    int i, rc;

    memset(config, 0, sizeof(*config));

    config->dsdt_anycpu = config->dsdt_15cpu = dsdt_empty;
    config->dsdt_anycpu_len = config->dsdt_15cpu_len = dsdt_empty_len;

    rc = xc_domain_getinfo(xch, domid, 1, &info);
    if ( rc < 0 )
    {
        DOMPRINTF("%s: getdomaininfo failed (rc=%d)", __FUNCTION__, rc);
        return rc;
    }

    config->apic_mode = 1;

    if ( dom->nr_vnodes )
    {
        struct acpi_numa *numa = &config->numa;

        numa->vmemrange = calloc(dom->nr_vmemranges,
                                 sizeof(*numa->vmemrange));
        numa->vdistance = calloc(dom->nr_vnodes,
                                 sizeof(*numa->vdistance));
        numa->vcpu_to_vnode = calloc(config->nr_vcpus,
                                     sizeof(*numa->vcpu_to_vnode));
        if ( !numa->vmemrange || !numa->vdistance || !numa->vcpu_to_vnode )
        {
            DOMPRINTF("%s: Out of memory", __FUNCTION__);
            free(numa->vmemrange);
            free(numa->vdistance);
            free(numa->vcpu_to_vnode);
            return -ENOMEM;
        }

        rc = xc_domain_getvnuma(xch, domid, &numa->nr_vnodes,
                                &numa->nr_vmemranges,
                                &config->nr_vcpus, numa->vmemrange,
                                numa->vdistance, numa->vcpu_to_vnode);

	    if ( rc )
        {
            DOMPRINTF("%s: xc_domain_getvnuma failed (rc=%d)", __FUNCTION__, rc);
            return rc;
        }
    }
    else
        config->nr_vcpus = info.max_vcpu_id + 1;

    config->vcpu_online = calloc((HVM_MAX_VCPUS + 7) / 8,
                                 sizeof(*config->vcpu_online));
    if ( config->vcpu_online == NULL )
    {
        DOMPRINTF("%s: Can't allocate vcpu_online", __FUNCTION__);
        return -ENOMEM;
    }

    for (i=0; i<config->nr_vcpus; i++)
        config->vcpu_online[i / 8] |= 1 << (i & 7);

    config->mem_ops.alloc = mem_alloc;
    config->mem_ops.v2p = virt_to_phys;

    return 0;
}

int xc_dom_build_acpi(struct xc_dom_image *dom)
{
    struct acpi_config config;
    uint32_t domid = dom->guest_domid;
    xc_interface *xch = dom->xch;
    int rc, i, acpi_pages_num = 0;
    xen_pfn_t extent, *extents = NULL;
    void *acpi_pages = NULL, *acpi_physical = NULL;
    void *guest_info_page = NULL, *guest_acpi_pages = NULL;

    rc = init_acpi_config(dom, &config);
    if ( rc )
    {
        DOMPRINTF("%s: init_acpi_config failed (rc=%d)", __FUNCTION__, rc);
        return rc;
    }

    /*
     * Pages to hold ACPI tables and one page for acpi_info, which
     * will be the first one in this region.
     */
    acpi_pages = xc_memalign(xch, PAGE_SIZE, NUM_ACPI_PAGES * PAGE_SIZE);
    if ( !acpi_pages )
    {
        DOMPRINTF("%s: Can't allocate acpi pages", __FUNCTION__);
        rc = -1;
        goto out;
    }

    config.acpi_info_page = acpi_pages;

    /* Set up allocator memory */
    base_addr = alloc_up = (unsigned long)acpi_pages + PAGE_SIZE;
    alloc_down = (unsigned long)acpi_pages + (NUM_ACPI_PAGES * PAGE_SIZE);

    /* Map page that will hold RSDP */
    extent = PFN(ACPI_PHYSICAL_ADDRESS);
    rc = xc_domain_populate_physmap_exact(xch, domid, 1, 0, 0, &extent);
    if ( rc )
    {
        DOMPRINTF("%s: xc_domain_populate_physmap failed with %d",
                  __FUNCTION__, rc);
        goto out;
    }
    acpi_physical = xc_map_foreign_range(xch, domid, PAGE_SIZE,
                                         PROT_READ | PROT_WRITE,
                                         PFN(ACPI_PHYSICAL_ADDRESS));
    if ( !acpi_physical )
    {
        DOMPRINTF("%s: Can't map acpi_physical", __FUNCTION__);
        rc = -1;
        goto out;
    }

    /* Build the tables */
    acpi_build_tables(&config, (unsigned long)acpi_physical);

    /* Copy acpi_info page into guest's memory */
    extent = PFN(ACPI_INFO_PHYSICAL_ADDRESS);
    rc = xc_domain_populate_physmap_exact(xch, domid, 1, 0, 0, &extent);
    if ( rc )
    {
        DOMPRINTF("%s: xc_domain_populate_physmap failed with %d\n",
                  __FUNCTION__, rc);
        goto out;
    }
    guest_info_page = xc_map_foreign_range(xch, domid, PAGE_SIZE,
                                           PROT_READ | PROT_WRITE,
                                           PFN(ACPI_INFO_PHYSICAL_ADDRESS));
    if ( !guest_info_page )
    {
        DOMPRINTF("%s: Can't map acpi_info_page", __FUNCTION__);
        rc = -1;
        goto out;
    }
    memcpy(guest_info_page, acpi_pages, PAGE_SIZE);

    /* Copy ACPI tables into guest's memory */
    acpi_pages_num = ((alloc_up - (unsigned long)acpi_pages +
                       (PAGE_SIZE - 1)) >> PAGE_SHIFT) - 1;
    extents = malloc(acpi_pages_num * sizeof(*extents));
    if ( !extents )
    {
        DOMPRINTF("%s: Can't allocate extents array", __FUNCTION__);
        rc = -ENOMEM;
        goto out;
    }
    for (i = 0; i < acpi_pages_num; i++)
        extents[i] = PFN(RESERVED_MEMORY_DYNAMIC_START) + i;
    rc = xc_domain_populate_physmap_exact(xch, domid, acpi_pages_num,
                                          0, 0, extents);
    if ( rc )
    {
        DOMPRINTF("%s: xc_domain_populate_physmap failed with %d",
                  __FUNCTION__, rc);
        goto out;
    }
    guest_acpi_pages = xc_map_foreign_range(xch, domid,
                                            PAGE_SIZE * acpi_pages_num,
                                            PROT_READ | PROT_WRITE,
                                            PFN(RESERVED_MEMORY_DYNAMIC_START));
    if ( !guest_acpi_pages )
    {
        DOMPRINTF("%s Can't map guest_acpi_pages", __FUNCTION__);
        rc = -1;
        goto out;
    }

    memcpy(guest_acpi_pages, acpi_pages + PAGE_SIZE,
           acpi_pages_num * PAGE_SIZE);

out:
    munmap(guest_acpi_pages, acpi_pages_num * PAGE_SIZE);
    munmap(guest_info_page, PAGE_SIZE);
    munmap(acpi_physical, PAGE_SIZE);
    free(extents);
    free(acpi_pages);
    free(config.vcpu_online);
    free(config.numa.vmemrange);
    free(config.numa.vdistance);
    free(config.numa.vcpu_to_vnode);

    return rc;
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
