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
#define VPCI_SECTION ".rodata.vpci"
#else
#define VPCI_SECTION ".init.rodata.vpci"
#endif

#define REGISTER_VPCI_INIT(x)                   \
  static vpci_register_init_t *const x##_entry  \
               __used_section(VPCI_SECTION) = x

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
