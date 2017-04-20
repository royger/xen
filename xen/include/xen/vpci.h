#ifndef _VPCI_
#define _VPCI_

#include <xen/pci.h>
#include <xen/types.h>

/* Helpers for locking/unlocking. */
#define vpci_lock(d) spin_lock(&(d)->arch.hvm_domain.vpci_lock)
#define vpci_unlock(d) spin_unlock(&(d)->arch.hvm_domain.vpci_lock)
#define vpci_locked(d) spin_is_locked(&(d)->arch.hvm_domain.vpci_lock)

/* Value read or written by the handlers. */
union vpci_val {
    uint8_t half_word;
    uint16_t word;
    uint32_t double_word;
};

/*
 * The vPCI handlers will never be called concurrently for the same domain, ii
 * is guaranteed that the vpci domain lock will always be locked when calling
 * any handler.
 */
typedef int (*vpci_read_t)(struct pci_dev *pdev, unsigned int reg,
                           union vpci_val *val, void *data);

typedef int (*vpci_write_t)(struct pci_dev *pdev, unsigned int reg,
                            union vpci_val val, void *data);

typedef int (*vpci_register_init_t)(struct pci_dev *dev);

struct vpci_register_init {
    vpci_register_init_t init;
    bool priority;
};

#define REGISTER_VPCI_INIT(f, p)                                        \
  static const struct vpci_register_init                                \
                      x##_entry __used_section(".data.vpci") = {        \
    .init = f,                                                          \
    .priority = p,                                                      \
}

/* Add vPCI handlers to device. */
int xen_vpci_add_handlers(struct pci_dev *dev);

/* Add/remove a register handler. */
int xen_vpci_add_register(struct pci_dev *pdev, vpci_read_t read_handler,
                          vpci_write_t write_handler, unsigned int offset,
                          unsigned int size, void *data);
int xen_vpci_remove_register(struct pci_dev *pdev, unsigned int offset);

/* Generic read/write handlers for the PCI config space. */
int xen_vpci_read(unsigned int seg, unsigned int bus, unsigned int devfn,
                  unsigned int reg, uint32_t size, uint32_t *data);
int xen_vpci_write(unsigned int seg, unsigned int bus, unsigned int devfn,
                   unsigned int reg, uint32_t size, uint32_t data);

struct vpci {
    /* Root pointer for the tree of vPCI handlers. */
    struct rb_root handlers;

#ifdef __XEN__
    /* Hide the rest of the vpci struct from the user-space test harness. */
    struct vpci_header {
        /* Cached value of the command register. */
        uint16_t command;
        /* Information about the PCI BARs of this device. */
        struct vpci_bar {
            enum {
                VPCI_BAR_EMPTY,
                VPCI_BAR_IO,
                VPCI_BAR_MEM,
                VPCI_BAR_MEM64_LO,
                VPCI_BAR_MEM64_HI,
            } type;
            /* Hardware address. */
            paddr_t paddr;
            /* Guest address where the BAR should be mapped. */
            paddr_t gaddr;
            /* Current guest address where the BAR is mapped. */
            paddr_t mapped_addr;
            size_t size;
            unsigned int attributes:4;
            bool sizing;
        } bars[6];
    } header;

    /* List of capabilities supported by the device. */
    struct list_head cap_list;

    /* MSI data. */
    struct vpci_msi {
        /* Maximum number of vectors supported by the device. */
        unsigned int max_vectors;
        /* Current guest-written number of vectors. */
        unsigned int guest_vectors;
        /* Number of vectors configured. */
        unsigned int vectors;
        /* Address and data fields. */
        uint64_t address;
        uint16_t data;
        /* PIRQ */
        int pirq;
        /* Mask bitfield. */
        uint32_t mask;
        /* MSI enabled? */
        bool enabled;
        /* Supports per-vector masking? */
        bool masking;
        /* 64-bit address capable? */
        bool address64;
    } *msi;

    /* MSI-X data. */
    struct vpci_msix {
        struct pci_dev *pdev;
        /* Maximum number of vectors supported by the device. */
        unsigned int max_entries;
        /* MSI-X table offset. */
        unsigned int offset;
        /* MSI-X table BIR. */
        unsigned int bir;
        /* Table addr. */
        paddr_t addr;
        /* MSI-X enabled? */
        bool enabled;
        /* Masked? */
        bool masked;
        /* List link. */
        struct list_head next;
        /* Entries. */
        struct vpci_msix_entry {
                unsigned int nr;
                uint64_t addr;
                uint32_t data;
                bool masked;
                int pirq;
          } entries[];
    } *msix;
#endif
};

/* Mask a PCI capability. */
void xen_vpci_mask_capability(struct pci_dev *pdev, uint8_t cap_id);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

