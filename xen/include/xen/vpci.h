#ifndef _XEN_VPCI_H_
#define _XEN_VPCI_H_

#ifdef CONFIG_HAS_PCI

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
int __must_check vpci_add_register(struct vpci *vpci,
                                   vpci_read_t *read_handler,
                                   vpci_write_t *write_handler,
                                   unsigned int offset, unsigned int size,
                                   void *data);
int __must_check vpci_remove_register(struct vpci *vpci, unsigned int offset,
                                      unsigned int size);

/* Generic read/write handlers for the PCI config space. */
uint32_t vpci_read(pci_sbdf_t sbdf, unsigned int reg, unsigned int size);
void vpci_write(pci_sbdf_t sbdf, unsigned int reg, unsigned int size,
                uint32_t data);

/* Passthrough handlers. */
uint32_t vpci_hw_read16(const struct pci_dev *pdev, unsigned int reg,
                        void *data);
uint32_t vpci_hw_read32(const struct pci_dev *pdev, unsigned int reg,
                        void *data);

/*
 * Check for pending vPCI operations on this vcpu. Returns true if the vcpu
 * should not run.
 */
bool __must_check vpci_process_pending(struct vcpu *v);

struct vpci {
    /* List of vPCI handlers for a device. */
    struct list_head handlers;
    spinlock_t lock;

#ifdef __XEN__
    /* Hide the rest of the vpci struct from the user-space test harness. */
    struct vpci_header {
        /* Information about the PCI BARs of this device. */
        struct vpci_bar {
            uint64_t addr;
            uint64_t size;
            enum {
                VPCI_BAR_EMPTY,
                VPCI_BAR_IO,
                VPCI_BAR_MEM32,
                VPCI_BAR_MEM64_LO,
                VPCI_BAR_MEM64_HI,
                VPCI_BAR_ROM,
            } type;
            bool prefetchable : 1;
            /* Store whether the BAR is mapped into guest p2m. */
            bool enabled      : 1;
            /*
             * Store whether the ROM enable bit is set (doesn't imply ROM BAR
             * is mapped into guest p2m). Only used for type VPCI_BAR_ROM.
             */
            bool rom_enabled  : 1;
        } bars[7]; /* At most 6 BARS + 1 expansion ROM BAR. */
        /* FIXME: currently there's no support for SR-IOV. */
    } header;

    /* MSI data. */
    struct vpci_msi {
        /* Address. */
        uint64_t address;
        /* Mask bitfield. */
        uint32_t mask;
        /* Data. */
        uint16_t data;
        /* Maximum number of vectors supported by the device. */
        uint8_t max_vectors : 5;
        /* Number of vectors configured. */
        uint8_t vectors     : 5;
        /* Enabled? */
        bool enabled        : 1;
        /* Supports per-vector masking? */
        bool masking        : 1;
        /* 64-bit address capable? */
        bool address64      : 1;
        /* Arch-specific data. */
        struct vpci_arch_msi arch;
    } *msi;

    /* MSI-X data. */
    struct vpci_msix {
        struct pci_dev *pdev;
        /* List link. */
        struct list_head next;
        /* Table information. */
#define VPCI_MSIX_TABLE     0
#define VPCI_MSIX_PBA       1
#define VPCI_MSIX_MEM_NUM   2
        uint32_t tables[VPCI_MSIX_MEM_NUM];
        /* Maximum number of vectors supported by the device. */
        uint16_t max_entries : 11;
        /* MSI-X enabled? */
        bool enabled         : 1;
        /* Masked? */
        bool masked          : 1;
        /* Entries. */
        struct vpci_msix_entry {
            uint64_t addr;
            uint32_t data;
            bool masked  : 1;
            bool updated : 1;
            struct vpci_arch_msix_entry arch;
        } entries[];
    } *msix;
#endif
};

#ifdef __XEN__
struct vpci_vcpu {
    struct rangeset *mem;
    const struct pci_dev *pdev;
    bool map : 1;
    bool rom : 1;
};

void vpci_dump_msi(void);

/* Arch-specific vPCI MSI helpers. */
void vpci_msi_arch_mask(struct vpci_msi *msi, const struct pci_dev *pdev,
                        unsigned int entry, bool mask);
int __must_check vpci_msi_arch_enable(struct vpci_msi *msi,
                                      const struct pci_dev *pdev,
                                      unsigned int vectors);
void vpci_msi_arch_disable(struct vpci_msi *msi, const struct pci_dev *pdev);
void vpci_msi_arch_init(struct vpci_msi *msi);
void vpci_msi_arch_print(const struct vpci_msi *msi);

/* Arch-specific vPCI MSI-X helpers. */
void vpci_msix_arch_mask_entry(struct vpci_msix_entry *entry,
                               const struct pci_dev *pdev, bool mask);
int __must_check vpci_msix_arch_enable_entry(struct vpci_msix_entry *entry,
                                             const struct pci_dev *pdev,
                                             paddr_t table_base);
int __must_check vpci_msix_arch_disable_entry(struct vpci_msix_entry *entry,
                                              const struct pci_dev *pdev);
void vpci_msix_arch_init_entry(struct vpci_msix_entry *entry);
void vpci_msix_arch_print_entry(const struct vpci_msix_entry *entry);

/*
 * Helper functions to fetch MSIX related data. They are used by both the
 * emulated MSIX code and the BAR handlers.
 */
#define VMSIX_TABLE_BASE(vpci, nr)                                        \
    ((vpci)->header.bars[(vpci)->msix->tables[nr] & PCI_MSIX_BIRMASK].addr)
#define VMSIX_TABLE_ADDR(vpci, nr)                                        \
    (VMSIX_TABLE_BASE(vpci, nr) +                                         \
     ((vpci)->msix->tables[nr] & ~PCI_MSIX_BIRMASK))

/*
 * Note regarding the size calculation of the PBA: the spec mentions "The last
 * QWORD will not necessarily be fully populated", so it implies that the PBA
 * size is 64-bit aligned.
 */
#define VMSIX_TABLE_SIZE(vpci, nr)                                             \
    ((nr == VPCI_MSIX_TABLE) ? (vpci)->msix->max_entries * PCI_MSIX_ENTRY_SIZE \
                             : ROUNDUP(DIV_ROUND_UP((vpci)->msix->max_entries, \
                                                    8), 8))

#define VMSIX_ENTRY_NR(msix, entry)                                       \
    (unsigned int)((entry) - (msix)->entries)

#endif

#else /* !CONFIG_HAS_PCI */
struct vpci_vpcu {
};
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
