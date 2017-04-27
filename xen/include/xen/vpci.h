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

#define REGISTER_VPCI_INIT(x) \
  static const vpci_register_init_t x##_entry __used_section(".data.vpci") = x

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
            bool unset;
        } bars[6];
    } header;
#endif
};

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

