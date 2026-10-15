/* Independent API-effect fixtures for a versioned RT context manifest.
 * These model manifest semantics; they are not real Kconfig or kernel builds.
 */
#include "fixture-context.h"

extern void p3_rt_wait_effect(void);
extern void p3_ordinary_sleep_effect(void);
extern void p3_opaque_effect(void);
extern void raw_spin_lock(raw_spinlock_t *);
extern void raw_spin_unlock(raw_spinlock_t *);
extern void rt_spin_lock(spinlock_t *);
extern void rt_spin_unlock(spinlock_t *);

void p3_case_task_wait(void) { p3_rt_wait_effect(); }
void p3_case_preempt_wait(void) { p3_rt_wait_effect(); }
void p3_case_irq_off_wait(void) { p3_rt_wait_effect(); }
void p3_case_hardirq_wait(void) { p3_rt_wait_effect(); }
void p3_case_nmi_wait(void) { p3_rt_wait_effect(); }
void p3_case_bh_wait(void) { p3_rt_wait_effect(); }
void p3_case_rcu_wait(void) { p3_rt_wait_effect(); }
void p3_case_migration_wait(void) { p3_rt_wait_effect(); }
void p3_case_softirq_wait(void) { p3_rt_wait_effect(); }
void p3_case_threaded_irq_wait(void) { p3_rt_wait_effect(); }
void p3_case_raw_wait(void) {
  raw_spinlock_t lock;
  raw_spin_lock(&lock);
  p3_rt_wait_effect();
  raw_spin_unlock(&lock);
}
void p3_case_task_sleep(void) { p3_ordinary_sleep_effect(); }
void p3_case_hardirq_sleep(void) { p3_ordinary_sleep_effect(); }
void p3_case_rcu_sleep(void) { p3_ordinary_sleep_effect(); }
void p3_case_unknown_effect(void) { p3_opaque_effect(); }
void p3_case_unknown_keeps_prior_witness(void) {
  p3_rt_wait_effect();
  p3_opaque_effect();
  p3_rt_wait_effect();
}
void p3_case_validation(void) { p3_rt_wait_effect(); }
void p3_case_no_manifest(void) {
  raw_spinlock_t raw;
  spinlock_t rt;
  raw_spin_lock(&raw);
  rt_spin_lock(&rt);
  rt_spin_unlock(&rt);
  raw_spin_unlock(&raw);
}
static inline void p3_inline_entry(void) { p3_rt_wait_effect(); }
void p3_case_inline_isolation(void) { p3_inline_entry(); }
