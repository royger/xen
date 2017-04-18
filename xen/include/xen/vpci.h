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

