/*
 * vpt.c: Virtual Platform Timer
 *
 * Copyright (c) 2006, Xiaowei Yang, Intel Corporation.
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

#include <xen/time.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vpt.h>
#include <asm/event.h>
#include <asm/apic.h>
#include <asm/mc146818rtc.h>
#include <public/hvm/params.h>

#define mode_is(d, name) \
    ((d)->arch.hvm.params[HVM_PARAM_TIMER_MODE] == HVMPTM_##name)

static bool inject_interrupt(struct periodic_time *pt);

void hvm_init_guest_time(struct domain *d)
{
    struct pl_time *pl = d->arch.hvm.pl_time;

    spin_lock_init(&pl->pl_time_lock);
    pl->stime_offset = -(u64)get_s_time();
    pl->last_guest_time = 0;
}

uint64_t hvm_get_guest_time_fixed(const struct vcpu *v, uint64_t at_tsc)
{
    struct pl_time *pl = v->domain->arch.hvm.pl_time;
    u64 now;

    /* Called from device models shared with PV guests. Be careful. */
    ASSERT(is_hvm_vcpu(v));

    spin_lock(&pl->pl_time_lock);
    now = get_s_time_fixed(at_tsc) + pl->stime_offset;

    if ( !at_tsc )
    {
        if ( (int64_t)(now - pl->last_guest_time) > 0 )
            pl->last_guest_time = now;
        else
            now = ++pl->last_guest_time;
    }
    spin_unlock(&pl->pl_time_lock);

    return now + v->arch.hvm.stime_offset;
}

void hvm_set_guest_time(struct vcpu *v, u64 guest_time)
{
    u64 offset = guest_time - hvm_get_guest_time(v);

    if ( offset )
    {
        v->arch.hvm.stime_offset += offset;
        /*
         * If hvm.stime_offset is updated make sure to
         * also update vcpu time, since this value is used to
         * calculate the TSC.
         */
        if ( v == current )
            update_vcpu_system_time(v);
    }
}

static int pt_irq_masked(struct periodic_time *pt)
{
    struct vcpu *v = pt->vcpu;
    unsigned int gsi = pt->irq;

    switch ( pt->source )
    {
    case PTSRC_lapic:
    {
        struct vlapic *vlapic = vcpu_vlapic(v);

        return (!vlapic_enabled(vlapic) ||
                (vlapic_get_reg(vlapic, APIC_LVTT) & APIC_LVT_MASKED));
    }

    case PTSRC_isa:
    {
        uint8_t pic_imr = v->domain->arch.hvm.vpic[pt->irq >> 3].imr;

        /* Check if the interrupt is unmasked in the PIC. */
        if ( !(pic_imr & (1 << (pt->irq & 7))) && vlapic_accept_pic_intr(v) )
            return 0;

        gsi = hvm_isa_irq_to_gsi(pt->irq);
    }

    /* Fallthrough to check if the interrupt is masked on the IO APIC. */
    case PTSRC_ioapic:
    {
        int mask = vioapic_get_mask(v->domain, gsi);

        if ( mask < 0 )
        {
            dprintk(XENLOG_WARNING,
                    "d%d: invalid GSI (%u) for platform timer\n",
                    v->domain->domain_id, gsi);
            domain_crash(v->domain);
            return -1;
        }

        return mask;
    }
    }

    ASSERT_UNREACHABLE();
    return 1;
}

static void pt_lock(struct periodic_time *pt)
{
    /*
     * We cannot use pt_vcpu_lock here, because we need to acquire the
     * per-domain lock first and then (re-)fetch the value of pt->vcpu, or
     * else we might be using a stale value of pt->vcpu.
     */
    read_lock(&pt->vcpu->domain->arch.hvm.pl_time->pt_migrate);
    spin_lock(&pt->vcpu->arch.hvm.tm_lock);
}

static void pt_unlock(struct periodic_time *pt)
{
    spin_unlock(&pt->vcpu->arch.hvm.tm_lock);
    read_unlock(&pt->vcpu->domain->arch.hvm.pl_time->pt_migrate);
}

static void pt_process_missed_ticks(struct periodic_time *pt)
{
    s_time_t missed_ticks, now = NOW();

    if ( pt->one_shot )
        return;

    missed_ticks = now - pt->scheduled;
    if ( missed_ticks <= 0 )
        return;

    missed_ticks = missed_ticks / (s_time_t) pt->period + 1;
    if ( !mode_is(pt->vcpu->domain, no_missed_ticks_pending) )
        pt->pending_intr_nr += missed_ticks;
    pt->scheduled += missed_ticks * pt->period;
}

static void pt_freeze_time(struct vcpu *v)
{
    if ( !mode_is(v->domain, delay_for_missed_ticks) )
        return;

    v->arch.hvm.guest_time = hvm_get_guest_time(v);
}

static void pt_thaw_time(struct vcpu *v)
{
    if ( !mode_is(v->domain, delay_for_missed_ticks) )
        return;

    if ( v->arch.hvm.guest_time == 0 )
        return;

    hvm_set_guest_time(v, v->arch.hvm.guest_time);
    v->arch.hvm.guest_time = 0;
}

void pt_save_timer(struct vcpu *v)
{

    pt_freeze_time(v);
}

void pt_restore_timer(struct vcpu *v)
{
    pt_thaw_time(v);
}

static void pt_irq_fired(struct vcpu *v, struct periodic_time *pt)
{
    if ( pt->one_shot )
    {
        pt->pending_intr_nr = 0;
        return;
    }

    if ( mode_is(v->domain, one_missed_tick_pending) ||
         mode_is(v->domain, no_missed_ticks_pending) )
    {
        pt_process_missed_ticks(pt);
        pt->pending_intr_nr = 0; /* 'collapse' all missed ticks */
    }
    else if ( !pt->pending_intr_nr )
        pt_process_missed_ticks(pt);

    if ( !pt->pending_intr_nr )
    {
        /* Make sure timer follows vCPU. */
        migrate_timer(&pt->timer, current->processor);
        set_timer(&pt->timer, pt->scheduled);
    }
}

static void pt_timer_fn(void *data)
{
    struct periodic_time *pt = data;
    struct vcpu *v;
    time_cb *cb = NULL;
    void *cb_priv;
    unsigned int irq;

    pt_lock(pt);

    v = pt->vcpu;
    irq = pt->irq;

    pt->masked = !inject_interrupt(pt);
    pt->scheduled += pt->period;

    if ( pt->masked )
        pt->pending_intr_nr++;
    else
    {
        cb = pt->cb;
        cb_priv = pt->priv;
    }

    pt_unlock(pt);

    if ( cb )
        cb(v, cb_priv);
}

/*
 * The same callback is shared between LAPIC and PIC/IO-APIC based timers, as
 * we ignore the first parameter that's different between them.
 */
static void eoi_callback(unsigned int unused, void *data)
{
    struct periodic_time *pt = data;
    struct vcpu *v;
    time_cb *cb = NULL;
    void *cb_priv;

    pt_lock(pt);

    pt_irq_fired(pt->vcpu, pt);
    if ( pt->pending_intr_nr )
    {
        pt->masked = !inject_interrupt(pt);
        if ( !pt->masked )
        {
            pt->pending_intr_nr--;
            cb = pt->cb;
            cb_priv = pt->priv;
            v = pt->vcpu;
        }
    }

    pt_unlock(pt);

    if ( cb != NULL )
        cb(v, cb_priv);
}

static bool inject_interrupt(struct periodic_time *pt)
{
    struct vcpu *v = pt->vcpu;
    unsigned int irq = pt->irq;

    if ( pt_irq_masked(pt) )
        return false;

    switch ( pt->source )
    {
    case PTSRC_lapic:
        vlapic_set_irq_callback(vcpu_vlapic(v), pt->irq, 0, eoi_callback, pt);
        break;

    case PTSRC_isa:
        hvm_isa_irq_deassert(v->domain, irq);
        if ( platform_legacy_irq(irq) && vlapic_accept_pic_intr(v) &&
             v->domain->arch.hvm.vpic[irq >> 3].int_output )
            hvm_isa_irq_assert(v->domain, irq, NULL);
        else
            hvm_isa_irq_assert(v->domain, irq, vioapic_get_vector);
        break;

    case PTSRC_ioapic:
        hvm_ioapic_assert(v->domain, irq, pt->level);
        break;
    }

    /* Update time when an interrupt is injected. */
    if ( mode_is(v->domain, one_missed_tick_pending) ||
         mode_is(v->domain, no_missed_ticks_pending) )
        pt->last_plt_gtime = hvm_get_guest_time(v);
    else
        pt->last_plt_gtime += pt->period;

    if ( mode_is(v->domain, delay_for_missed_ticks) &&
         hvm_get_guest_time(v) < pt->last_plt_gtime )
        hvm_set_guest_time(v, pt->last_plt_gtime);

    return true;
}

void create_periodic_time(
    struct vcpu *v, struct periodic_time *pt, uint64_t delta,
    uint64_t period, uint8_t irq, time_cb *cb, void *data, bool level)
{
    if ( !pt->source ||
         (irq >= NR_ISAIRQS && pt->source == PTSRC_isa) ||
         (level && period) ||
         (pt->source == PTSRC_ioapic ? irq >= hvm_domain_irq(v->domain)->nr_gsis
                                     : level) )
    {
        ASSERT_UNREACHABLE();
        return;
    }

    destroy_periodic_time(pt);

    write_lock(&v->domain->arch.hvm.pl_time->pt_migrate);

    pt->pending_intr_nr = 0;
    pt->masked = false;

    /* Periodic timer must be at least 0.1ms. */
    if ( (period < 100000) && period )
    {
        if ( !test_and_set_bool(pt->warned_timeout_too_short) )
            gdprintk(XENLOG_WARNING, "HVM_PlatformTime: program too "
                     "small period %"PRIu64"\n", period);
        period = 100000;
    }

    pt->period = period;
    pt->vcpu = v;
    pt->last_plt_gtime = hvm_get_guest_time(pt->vcpu);
    pt->irq = irq;
    pt->one_shot = !period;
    pt->level = level;
    pt->scheduled = NOW() + delta;

    if ( !pt->one_shot )
    {
        if ( v->domain->arch.hvm.params[HVM_PARAM_VPT_ALIGN] )
        {
            pt->scheduled = align_timer(pt->scheduled, pt->period);
        }
        else if ( pt->source == PTSRC_lapic )
        {
            /*
             * Offset LAPIC ticks from other timer ticks. Otherwise guests
             * which use LAPIC ticks for process accounting can see long
             * sequences of process ticks incorrectly accounted to interrupt
             * processing (seen with RHEL3 guest).
             */
            pt->scheduled += delta >> 1;
        }
    }

    pt->cb = cb;
    pt->priv = data;

    switch ( pt->source )
    {
        int rc;

    case PTSRC_isa:
        irq = hvm_isa_irq_to_gsi(irq);
        /* fallthrough */
    case PTSRC_ioapic:
        pt->eoi_cb.callback = eoi_callback;
        pt->eoi_cb.data = pt;
        rc = hvm_gsi_register_callback(v->domain, irq, &pt->eoi_cb);
        if ( rc )
            gdprintk(XENLOG_WARNING,
                     "unable to register callback for timer GSI %u: %d\n",
                     irq, rc);
        break;
    }

    init_timer(&pt->timer, pt_timer_fn, pt, v->processor);
    set_timer(&pt->timer, pt->scheduled);

    write_unlock(&v->domain->arch.hvm.pl_time->pt_migrate);
}

void destroy_periodic_time(struct periodic_time *pt)
{
    unsigned int gsi;

    /* Was this structure previously initialised by create_periodic_time()? */
    if ( pt->vcpu == NULL )
        return;

    pt_lock(pt);
    pt->pending_intr_nr = 0;
    pt->masked = false;

    gsi = pt->irq;
    switch ( pt->source )
    {
    case PTSRC_isa:
        gsi = hvm_isa_irq_to_gsi(pt->irq);
        /* fallthrough */
    case PTSRC_ioapic:
        hvm_gsi_unregister_callback(pt->vcpu->domain, gsi, &pt->eoi_cb);
        break;
    }
    pt_unlock(pt);

    /*
     * pt_timer_fn() can run until this kill_timer() returns. We must do this
     * outside pt_lock() otherwise we can deadlock with pt_timer_fn().
     */
    kill_timer(&pt->timer);
}

static void pt_resume(struct periodic_time *pt)
{
    struct vcpu *v;
    time_cb *cb = NULL;
    void *cb_priv;

    if ( pt->vcpu == NULL )
        return;

    pt_lock(pt);
    if ( pt->pending_intr_nr && pt->masked && inject_interrupt(pt) )
    {
        pt->pending_intr_nr--;
        cb = pt->cb;
        cb_priv = pt->priv;
        v = pt->vcpu;
        pt->masked = false;
    }
    pt_unlock(pt);

    if ( cb )
        cb(v, cb_priv);
}

void pt_may_unmask_irq(struct domain *d, struct periodic_time *vlapic_pt)
{
    if ( d )
    {
        if ( has_vpit(d) )
            pt_resume(&d->arch.vpit.pt0);
        if ( has_vrtc(d) )
            pt_resume(&d->arch.hvm.pl_time->vrtc.pt);
        if ( has_vhpet(d) )
        {
            unsigned int i;

            for ( i = 0; i < HPET_TIMER_NUM; i++ )
                pt_resume(&d->arch.hvm.pl_time->vhpet.pt[i]);
        }
    }

    if ( vlapic_pt )
        pt_resume(vlapic_pt);
}
