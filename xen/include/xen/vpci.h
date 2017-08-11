#ifndef _VPCI_
#define _VPCI_

#include <xen/pci.h>
#include <xen/types.h>
#include <xen/list.h>

/*
 * Helpers for locking/unlocking.
 *
 * NB: the recursive variants are used so that spin_is_locked
 * returns whether the lock is hold by the current CPU (instead
 * of just returning whether the lock is hold by any CPU).
 */
#define vpci_rlock(d) read_lock(&(d)->arch.hvm_domain.vpci_lock)
#define vpci_tryrlock(d) read_trylock(&(d)->arch.hvm_domain.vpci_lock)
#define vpci_wlock(d) write_lock(&(d)->arch.hvm_domain.vpci_lock)
#define vpci_runlock(d) read_unlock(&(d)->arch.hvm_domain.vpci_lock)
#define vpci_wunlock(d) write_unlock(&(d)->arch.hvm_domain.vpci_lock)
#define vpci_rlocked(d) rw_is_locked(&(d)->arch.hvm_domain.vpci_lock)
#define vpci_wlocked(d) rw_is_write_locked(&(d)->arch.hvm_domain.vpci_lock)

/*
 * The vPCI handlers will never be called concurrently for the same domain, it
 * is guaranteed that the vpci domain lock will always be locked when calling
 * any handler.
 */
typedef uint32_t vpci_read_t(struct pci_dev *pdev, unsigned int reg,
                             const void *data);

typedef void vpci_write_t(struct pci_dev *pdev, unsigned int reg,
                          uint32_t val, void *data);

typedef int vpci_register_init_t(struct pci_dev *dev);

#ifdef CONFIG_LATE_HWDOM
#define VPCI_SECTION ".rodata.vpci."
#else
#define VPCI_SECTION ".init.rodata.vpci."
#endif

#define VPCI_PRIORITY_HIGH      "1"
#define VPCI_PRIORITY_MIDDLE    "5"
#define VPCI_PRIORITY_LOW       "9"

#define REGISTER_VPCI_INIT(x, p)                \
  static vpci_register_init_t *const x##_entry  \
               __used_section(VPCI_SECTION p) = x

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
uint32_t vpci_read(unsigned int seg, unsigned int bus, unsigned int slot,
                   unsigned int func, unsigned int reg, unsigned int size);
void vpci_write(unsigned int seg, unsigned int bus, unsigned int slot,
                unsigned int func, unsigned int reg, unsigned int size,
                uint32_t data);

struct vpci {
    /* List of vPCI handlers for a device. */
    struct list_head handlers;

#ifdef __XEN__
    /* Hide the rest of the vpci struct from the user-space test harness. */
    struct vpci_header {
        /* Information about the PCI BARs of this device. */
        struct vpci_bar {
            paddr_t addr;
            uint64_t size;
#define VPCI_BAR_MSIX_TABLE     0
#define VPCI_BAR_MSIX_PBA       1
#define VPCI_BAR_MSIX_NUM       2
            struct vpci_msix_mem *msix[VPCI_BAR_MSIX_NUM];
            enum {
                VPCI_BAR_EMPTY,
                VPCI_BAR_IO,
                VPCI_BAR_MEM32,
                VPCI_BAR_MEM64_LO,
                VPCI_BAR_MEM64_HI,
                VPCI_BAR_ROM,
            } type;
            bool prefetchable;
            bool sizing;
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
            /* Table addr. */
            paddr_t addr;
            /* Table size. */
            unsigned int size;
        } table;
        /* PBA */
        struct vpci_msix_mem pba;
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

void vpci_dump_msi(void);

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
