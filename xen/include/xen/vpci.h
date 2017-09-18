#ifndef _XEN_VPCI_H_
#define _XEN_VPCI_H_

#include <xen/pci.h>
#include <xen/types.h>
#include <xen/list.h>

typedef uint32_t vpci_read_t(const struct pci_dev *pdev, unsigned int reg,
                             void *data);

typedef void vpci_write_t(const struct pci_dev *pdev, unsigned int reg,
                          uint32_t val, void *data);

typedef int vpci_register_init_t(struct pci_dev *dev);

#define VPCI_PRIORITY_HIGH      "1"
#define VPCI_PRIORITY_MIDDLE    "5"
#define VPCI_PRIORITY_LOW       "9"

#define REGISTER_VPCI_INIT(x, p)                \
  static vpci_register_init_t *const x##_entry  \
               __used_section(".data.vpci." p) = x

/* Add vPCI handlers to device. */
int __must_check vpci_add_handlers(struct pci_dev *dev);

/* Add/remove a register handler. */
int __must_check vpci_add_register(const struct pci_dev *pdev,
                                   vpci_read_t *read_handler,
                                   vpci_write_t *write_handler,
                                   unsigned int offset, unsigned int size,
                                   void *data);
int __must_check vpci_remove_register(const struct pci_dev *pdev,
                                      unsigned int offset,
                                      unsigned int size);

/* Generic read/write handlers for the PCI config space. */
uint32_t vpci_read(pci_sbdf_t sbdf, unsigned int reg, unsigned int size);
void vpci_write(pci_sbdf_t sbdf, unsigned int reg, unsigned int size,
                uint32_t data);

/*
 * Check for pending vPCI operations on this vcpu. Returns true if the vcpu
 * should not run.
 */
bool vpci_check_pending(struct vcpu *v);

struct vpci {
    /* List of vPCI handlers for a device. */
    struct list_head handlers;
    spinlock_t lock;

#ifdef __XEN__
    /* Hide the rest of the vpci struct from the user-space test harness. */
    struct vpci_header {
        /* Information about the PCI BARs of this device. */
        struct vpci_bar {
            paddr_t addr;
            uint64_t size;
            enum {
                VPCI_BAR_EMPTY,
                VPCI_BAR_IO,
                VPCI_BAR_MEM32,
                VPCI_BAR_MEM64_LO,
                VPCI_BAR_MEM64_HI,
                VPCI_BAR_ROM,
            } type;
            bool prefetchable;
            /* Store whether the BAR is mapped into guest p2m. */
            bool enabled;
            /*
             * Store whether the ROM enable bit is set (doesn't imply ROM BAR
             * is mapped into guest p2m). Only used for type VPCI_BAR_ROM.
             */
            bool rom_enabled;
        } bars[7]; /* At most 6 BARS + 1 expansion ROM BAR. */
        /* FIXME: currently there's no support for SR-IOV. */
    } header;

    /* MSI data. */
    struct vpci_msi {
        /* Arch-specific data. */
        struct vpci_arch_msi arch;
        /* Address. */
        uint64_t address;
        /* Offset of the capability in the config space. */
        unsigned int pos;
        /* Maximum number of vectors supported by the device. */
        unsigned int max_vectors;
        /* Number of vectors configured. */
        unsigned int vectors;
        /* Mask bitfield. */
        uint32_t mask;
        /* Data. */
        uint16_t data;
        /* Enabled? */
        bool enabled;
        /* Supports per-vector masking? */
        bool masking;
        /* 64-bit address capable? */
        bool address64;
    } *msi;

    /* MSI-X data. */
    struct vpci_msix {
        struct pci_dev *pdev;
        /* List link. */
        struct list_head next;
        /* Table information. */
        struct vpci_msix_mem {
            /* MSI-X table offset. */
            unsigned int offset;
            /* MSI-X table BIR. */
            unsigned int bir;
            /* Table size. */
            unsigned int size;
#define VPCI_MSIX_TABLE     0
#define VPCI_MSIX_PBA       1
#define VPCI_MSIX_MEM_NUM   2
        } mem[VPCI_MSIX_MEM_NUM];
        /* Maximum number of vectors supported by the device. */
        unsigned int max_entries;
        /* MSI-X enabled? */
        bool enabled;
        /* Masked? */
        bool masked;
        /* Entries. */
        struct vpci_msix_entry {
            uint64_t addr;
            uint32_t data;
            unsigned int nr;
            struct vpci_arch_msix_entry arch;
            bool masked;
            bool updated;
        } entries[];
    } *msix;
#endif
};

#ifdef __XEN__
struct vpci_vcpu {
    struct rangeset *mem;
    bool map;
};

void vpci_dump_msi(void);

/* Arch-specific vPCI MSI helpers. */
void vpci_msi_arch_mask(struct vpci_msi *msi, const struct pci_dev *pdev,
                        unsigned int entry, bool mask);
int vpci_msi_arch_enable(struct vpci_msi *msi, const struct pci_dev *pdev,
                         unsigned int vectors);
int vpci_msi_arch_disable(struct vpci_msi *msi, const struct pci_dev *pdev);
void vpci_msi_arch_init(struct vpci_msi *msi);
void vpci_msi_arch_print(const struct vpci_msi *msi);

/* Arch-specific vPCI MSI-X helpers. */
void vpci_msix_arch_mask_entry(struct vpci_msix_entry *entry,
                               const struct pci_dev *pdev, bool mask);
int vpci_msix_arch_enable_entry(struct vpci_msix_entry *entry,
                                const struct pci_dev *pdev,
                                paddr_t table_base);
int vpci_msix_arch_disable_entry(struct vpci_msix_entry *entry,
                                 const struct pci_dev *pdev);
int vpci_msix_arch_init_entry(struct vpci_msix_entry *entry);
void vpci_msix_arch_print_entry(const struct vpci_msix_entry *entry);
#endif

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
