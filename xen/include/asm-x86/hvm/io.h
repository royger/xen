/*
 * io.h: HVM IO support
 *
 * Copyright (c) 2004, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_X86_HVM_IO_H__
#define __ASM_X86_HVM_IO_H__

#include <xen/pci_regs.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vioapic.h>
#include <public/hvm/ioreq.h>
#include <public/event_channel.h>

#define NR_IO_HANDLERS 32

typedef int (*hvm_mmio_read_t)(struct vcpu *v,
                               unsigned long addr,
                               unsigned int length,
                               unsigned long *val);
typedef int (*hvm_mmio_write_t)(struct vcpu *v,
                                unsigned long addr,
                                unsigned int length,
                                unsigned long val);
typedef int (*hvm_mmio_check_t)(struct vcpu *v, unsigned long addr);

struct hvm_mmio_ops {
    hvm_mmio_check_t check;
    hvm_mmio_read_t  read;
    hvm_mmio_write_t write;
};

static inline paddr_t hvm_mmio_first_byte(const ioreq_t *p)
{
    return unlikely(p->df) ?
           p->addr - (p->count - 1ul) * p->size :
           p->addr;
}

static inline paddr_t hvm_mmio_last_byte(const ioreq_t *p)
{
    unsigned long size = p->size;

    return unlikely(p->df) ?
           p->addr + size - 1:
           p->addr + (p->count * size) - 1;
}

typedef int (*portio_action_t)(
    int dir, unsigned int port, unsigned int bytes, uint32_t *val);

struct hvm_io_handler {
    union {
        struct {
            const struct hvm_mmio_ops *ops;
        } mmio;
        struct {
            unsigned int port, size;
            portio_action_t action;
        } portio;
    };
    const struct hvm_io_ops *ops;
    uint8_t type;
};

typedef int (*hvm_io_read_t)(const struct hvm_io_handler *,
                             uint64_t addr,
                             uint32_t size,
                             uint64_t *data);
typedef int (*hvm_io_write_t)(const struct hvm_io_handler *,
                              uint64_t addr,
                              uint32_t size,
                              uint64_t data);
typedef bool_t (*hvm_io_accept_t)(const struct hvm_io_handler *,
                                  const ioreq_t *p);
typedef void (*hvm_io_complete_t)(const struct hvm_io_handler *);

struct hvm_io_ops {
    hvm_io_accept_t   accept;
    hvm_io_read_t     read;
    hvm_io_write_t    write;
    hvm_io_complete_t complete;
};

int hvm_process_io_intercept(const struct hvm_io_handler *handler,
                             ioreq_t *p);

const struct hvm_io_handler *hvm_find_io_handler(ioreq_t *p);

int hvm_io_intercept(ioreq_t *p);

struct hvm_io_handler *hvm_next_io_handler(struct domain *d);

bool_t hvm_mmio_internal(paddr_t gpa);

void register_mmio_handler(struct domain *d,
                           const struct hvm_mmio_ops *ops);

void register_portio_handler(
    struct domain *d, unsigned int port, unsigned int size,
    portio_action_t action);

void relocate_portio_handler(
    struct domain *d, unsigned int old_port, unsigned int new_port,
    unsigned int size);

void send_timeoffset_req(unsigned long timeoff);
void send_invalidate_req(void);
int handle_mmio(void);
int handle_mmio_with_translation(unsigned long gla, unsigned long gpfn,
                                 struct npfec);
int handle_pio(uint16_t port, unsigned int size, int dir);
void hvm_interrupt_post(struct vcpu *v, int vector, int type);
void hvm_dpci_eoi(struct domain *d, unsigned int guest_irq,
                  const union vioapic_redir_entry *ent);
void hvm_hw_dpci_eoi(struct domain *d, unsigned int gsi,
                     const union vioapic_redir_entry *ent);
void msix_write_completion(struct vcpu *);
void msixtbl_init(struct domain *d);

enum stdvga_cache_state {
    STDVGA_CACHE_UNINITIALIZED,
    STDVGA_CACHE_ENABLED,
    STDVGA_CACHE_DISABLED
};

struct hvm_hw_stdvga {
    uint8_t sr_index;
    uint8_t sr[8];
    uint8_t gr_index;
    uint8_t gr[9];
    bool_t stdvga;
    enum stdvga_cache_state cache;
    uint32_t latch;
    struct page_info *vram_page[64];  /* shadow of 0xa0000-0xaffff */
    spinlock_t lock;
};

void stdvga_init(struct domain *d);
void stdvga_deinit(struct domain *d);

extern void hvm_dpci_msi_eoi(struct domain *d, int vector);

void register_dpci_portio_handler(struct domain *d);

/* Structures for pci-passthrough state and handlers. */
struct hvm_pt_device;
struct hvm_pt_reg_handler;
struct hvm_pt_reg;
struct hvm_pt_reg_group;

/* Return code when register should be ignored. */
#define HVM_PT_INVALID_REG 0xFFFFFFFF

/* function type for config reg */
typedef int (*hvm_pt_conf_reg_init)
    (struct hvm_pt_device *, struct hvm_pt_reg_handler *, uint32_t real_offset,
     uint32_t *data);

typedef int (*hvm_pt_conf_dword_write)
    (struct hvm_pt_device *, struct hvm_pt_reg *cfg_entry,
     uint32_t *val, uint32_t dev_value, uint32_t valid_mask);
typedef int (*hvm_pt_conf_word_write)
    (struct hvm_pt_device *, struct hvm_pt_reg *cfg_entry,
     uint16_t *val, uint16_t dev_value, uint16_t valid_mask);
typedef int (*hvm_pt_conf_byte_write)
    (struct hvm_pt_device *, struct hvm_pt_reg *cfg_entry,
     uint8_t *val, uint8_t dev_value, uint8_t valid_mask);
typedef int (*hvm_pt_conf_dword_read)
    (struct hvm_pt_device *, struct hvm_pt_reg *cfg_entry,
     uint32_t *val, uint32_t valid_mask);
typedef int (*hvm_pt_conf_word_read)
    (struct hvm_pt_device *, struct hvm_pt_reg *cfg_entry,
     uint16_t *val, uint16_t valid_mask);
typedef int (*hvm_pt_conf_byte_read)
    (struct hvm_pt_device *, struct hvm_pt_reg *cfg_entry,
     uint8_t *val, uint8_t valid_mask);

typedef int (*hvm_pt_group_init)
    (struct hvm_pt_device *, struct hvm_pt_reg_group *);

/*
 * Emulated register information.
 *
 * This should be shared between all the consumers that trap on accesses
 * to certain PCI registers.
 */
struct hvm_pt_reg_handler {
    uint32_t offset;
    uint32_t size;
    uint32_t init_val;
    /* reg reserved field mask (ON:reserved, OFF:defined) */
    uint32_t res_mask;
    /* reg read only field mask (ON:RO/ROS, OFF:other) */
    uint32_t ro_mask;
    /* reg read/write-1-clear field mask (ON:RW1C/RW1CS, OFF:other) */
    uint32_t rw1c_mask;
    /* reg emulate field mask (ON:emu, OFF:passthrough) */
    uint32_t emu_mask;
    hvm_pt_conf_reg_init init;
    /* read/write function pointer
     * for double_word/word/byte size */
    union {
        struct {
            hvm_pt_conf_dword_write write;
            hvm_pt_conf_dword_read read;
        } dw;
        struct {
            hvm_pt_conf_word_write write;
            hvm_pt_conf_word_read read;
        } w;
        struct {
            hvm_pt_conf_byte_write write;
            hvm_pt_conf_byte_read read;
        } b;
    } u;
};

struct hvm_pt_handler_init {
    struct hvm_pt_reg_handler *handlers;
    hvm_pt_group_init init;
};

/*
 * Emulated register value.
 *
 * This is the representation of each specific emulated register.
 */
struct hvm_pt_reg {
    struct list_head entries;
    struct hvm_pt_reg_handler *handler;
    union {
        uint8_t   byte;
        uint16_t  word;
        uint32_t  dword;
    } val;
};

/*
 * Emulated register group.
 *
 * In order to speed up (and logically group) emulated registers search,
 * groups are used that represent specific emulated features, like MSI.
 */
struct hvm_pt_reg_group {
    struct list_head entries;
    uint32_t base_offset;
    uint8_t size;
    struct list_head registers;
};

/*
 * Guest MSI information.
 *
 * MSI values set by the guest.
 */
struct hvm_pt_msi {
    uint16_t flags;
    uint32_t addr_lo;  /* guest message address */
    uint32_t addr_hi;  /* guest message upper address */
    uint16_t data;     /* guest message data */
    uint32_t ctrl_offset; /* saved control offset */
    int pirq;          /* guest pirq corresponding */
    bool_t initialized;  /* when guest MSI is initialized */
    bool_t mapped;       /* when pirq is mapped */
};

struct hvm_pt_bar {
    uint32_t val;
    enum bar_type {
        HVM_PT_BAR_UNUSED,
        HVM_PT_BAR_MEM32,
        HVM_PT_BAR_MEM64_LO,
        HVM_PT_BAR_MEM64_HI,
    } type;
};

/*
 * Guest passed-through PCI device.
 */
struct hvm_pt_device {
    struct list_head entries;

    struct pci_dev *pdev;

    bool_t permissive;
    bool_t permissive_warned;

    /* MSI status. */
    struct hvm_pt_msi msi;

    /* PCI header type. */
    uint8_t htype;

    /* BAR tracking. */
    int num_bars;
    struct hvm_pt_bar bars[6];
    struct hvm_pt_bar vf_bars[PCI_SRIOV_NUM_BARS];

    struct list_head register_groups;
};

/*
 * The hierarchy of the above structures is the following:
 *
 * +---------------+         +---------------+
 * |               | entries |               | ...
 * | hvm_pt_device +---------+ hvm_pt_device +----+
 * |               |         |               |
 * +-+-------------+         +---------------+
 *   |
 *   | register_groups
 *   |
 * +-v----------------+          +------------------+
 * |                  | entries  |                  | ...
 * | hvm_pt_reg_group +----------+ hvm_pt_reg_group +----+
 * |                  |          |                  |
 * +-+----------------+          +------------------+
 *   |
 *   | registers
 *   |
 * +-v----------+            +------------+
 * |            | entries    |            | ...
 * | hvm_pt_reg +------------+ hvm_pt_reg +----+
 * |            |            |            |
 * +-+----------+            +-+----------+
 *   |                         |
 *   | handler                 | handler
 *   |                         |
 * +-v------------------+    +-v------------------+
 * |                    |    |                    |
 * | hvm_pt_reg_handler |    | hvm_pt_reg_handler |
 * |                    |    |                    |
 * +--------------------+    +--------------------+
 */

/* Helper to add passed-through devices to the hardware domain. */
int hwdom_add_device(struct pci_dev *pdev);

#endif /* __ASM_X86_HVM_IO_H__ */


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
