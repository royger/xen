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
#define vpci_lock(d) spin_lock_recursive(&(d)->arch.hvm_domain.vpci_lock)
#define vpci_trylock(d) spin_trylock_recursive(&(d)->arch.hvm_domain.vpci_lock)
#define vpci_unlock(d) spin_unlock_recursive(&(d)->arch.hvm_domain.vpci_lock)
#define vpci_locked(d) spin_is_locked(&(d)->arch.hvm_domain.vpci_lock)

/* Value read or written by the handlers. */
union vpci_val {
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
};

/*
 * The vPCI handlers will never be called concurrently for the same domain, ii
 * is guaranteed that the vpci domain lock will always be locked when calling
 * any handler.
 */
typedef void (vpci_read_t)(struct pci_dev *pdev, unsigned int reg,
                           union vpci_val *val, void *data);

typedef void (vpci_write_t)(struct pci_dev *pdev, unsigned int reg,
                            union vpci_val val, void *data);

typedef int (*vpci_register_init_t)(struct pci_dev *dev);

#define VPCI_PRIORITY_HIGH      "1"
#define VPCI_PRIORITY_LOW       "9"

#define REGISTER_VPCI_INIT(x, p)                        \
  static const vpci_register_init_t x##_entry           \
               __used_section(".rodata.vpci." p) = x

/* Add vPCI handlers to device. */
int __must_check vpci_add_handlers(struct pci_dev *dev);

/* Add/remove a register handler. */
int __must_check vpci_add_register(const struct pci_dev *pdev,
                                   vpci_read_t read_handler,
                                   vpci_write_t write_handler,
                                   unsigned int offset,
                                   unsigned int size, void *data);
int __must_check vpci_remove_register(const struct pci_dev *pdev,
                                      unsigned int offset,
                                      unsigned int size);

/* Generic read/write handlers for the PCI config space. */
uint32_t vpci_read(unsigned int seg, unsigned int bus, unsigned int slot,
                   unsigned int func, unsigned int reg, uint32_t size);
void vpci_write(unsigned int seg, unsigned int bus, unsigned int slot,
                unsigned int func, unsigned int reg, uint32_t size,
                uint32_t data);

struct vpci {
    /* Root pointer for the tree of vPCI handlers. */
    struct list_head handlers;

#ifdef __XEN__
    /* Hide the rest of the vpci struct from the user-space test harness. */
    struct vpci_header {
        /* Information about the PCI BARs of this device. */
        struct vpci_bar {
            enum {
                VPCI_BAR_EMPTY,
                VPCI_BAR_IO,
                VPCI_BAR_MEM32,
                VPCI_BAR_MEM64_LO,
                VPCI_BAR_MEM64_HI,
                VPCI_BAR_ROM,
            } type;
            paddr_t addr;
            uint64_t size;
            bool prefetchable;
            bool sizing;
            bool enabled;
        } bars[7]; /* At most 6 BARS + 1 expansion ROM BAR. */
        /* FIXME: currently there's no support for SR-IOV. */
    } header;

    /* MSI data. */
    struct vpci_msi {
        /* Offset of the capability in the config space. */
        unsigned int pos;
        /* Maximum number of vectors supported by the device. */
        unsigned int max_vectors;
        /* Number of vectors configured. */
        unsigned int vectors;
        /* Address and data fields. */
        uint64_t address;
        uint16_t data;
        /* Mask bitfield. */
        uint32_t mask;
        /* Enabled? */
        bool enabled;
        /* Supports per-vector masking? */
        bool masking;
        /* 64-bit address capable? */
        bool address64;
        /* Arch-specific data. */
        struct vpci_arch_msi arch;
    } *msi;
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

