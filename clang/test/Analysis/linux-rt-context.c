// RUN: %clang_analyze_cc1 -triple riscv64-unknown-linux-gnu \
// RUN:   -D CONFIG_PREEMPT_RT=1 \
// RUN:   -analyzer-checker=core,alpha.linux.AtomicSleep \
// RUN:   -analyzer-config alpha.linux.AtomicSleep:RTContext=true \
// RUN:   -verify=rt %s
// RUN: %clang_analyze_cc1 -triple riscv64-unknown-linux-gnu \
// RUN:   -D CONFIG_PREEMPT_RT=1 \
// RUN:   -analyzer-checker=core,alpha.linux.AtomicSleep \
// RUN:   -verify=default %s
// REQUIRES: riscv-registered-target
//
// default-no-diagnostics

typedef struct raw_spinlock { int v; } raw_spinlock_t;
typedef struct rt_spinlock { int v; } rt_spinlock_t;

void _raw_spin_lock(raw_spinlock_t *lock);
void _raw_spin_unlock(raw_spinlock_t *lock);
void raw_spin_lock(raw_spinlock_t *lock);
void raw_spin_unlock(raw_spinlock_t *lock);
void rt_spin_lock(rt_spinlock_t *lock);
void rt_spin_unlock(rt_spinlock_t *lock);

void preempt_disable(void);
void preempt_enable(void);
void local_bh_disable(void);
void local_bh_enable(void);
void __rcu_read_lock(void);
void __rcu_read_unlock(void);
void migrate_disable(void);
void migrate_enable(void);
void irq_enter(void);
void irq_exit(void);
void nmi_enter(void);
void nmi_exit(void);
void local_irq_disable(void);
void local_irq_enable(void);
unsigned long local_irq_save(void);
void local_irq_restore(unsigned long flags);
int irqs_disabled(void);
void preempt_count_add(int value);
void preempt_count_sub(int value);
void __local_bh_disable_ip(unsigned long ip, unsigned int count);
void __local_bh_enable_ip(unsigned long ip, unsigned int count);

void rt_wait_under_raw_spin(raw_spinlock_t *raw, rt_spinlock_t *rt) {
  _raw_spin_lock(raw);
  rt_spin_lock(rt); // rt-warning {{Call to RT lock 'rt_spin_lock' with a raw spinlock held}}
  rt_spin_unlock(rt);
  _raw_spin_unlock(raw);
}

void rt_wait_under_public_raw_spin(raw_spinlock_t *raw, rt_spinlock_t *rt) {
  raw_spin_lock(raw);
  rt_spin_lock(rt); // rt-warning {{Call to RT lock 'rt_spin_lock' with a raw spinlock held}}
  rt_spin_unlock(rt);
  raw_spin_unlock(raw);
}

void rt_wait_with_preemption_off(rt_spinlock_t *rt) {
  preempt_disable();
  rt_spin_lock(rt); // rt-warning {{Call to RT lock 'rt_spin_lock' with preemption disabled}}
  rt_spin_unlock(rt);
  preempt_enable();
}

void rt_wait_in_hardirq(rt_spinlock_t *rt) {
  irq_enter();
  rt_spin_lock(rt); // rt-warning {{Call to RT lock 'rt_spin_lock' inside a hard IRQ handler}}
  rt_spin_unlock(rt);
  irq_exit();
}

void rt_wait_in_nmi(rt_spinlock_t *rt) {
  nmi_enter();
  rt_spin_lock(rt); // rt-warning {{Call to RT lock 'rt_spin_lock' inside NMI context}}
  rt_spin_unlock(rt);
  nmi_exit();
}

void rt_wait_with_irqs_off(rt_spinlock_t *rt) {
  local_irq_disable();
  rt_spin_lock(rt); // rt-warning {{Call to RT lock 'rt_spin_lock' with hard interrupts disabled}}
  rt_spin_unlock(rt);
  local_irq_enable();
}

// These contexts do not forbid an rtmutex-backed spinlock wait on RT.
void rt_wait_under_rcu(rt_spinlock_t *rt) {
  __rcu_read_lock();
  rt_spin_lock(rt);
  rt_spin_unlock(rt);
  __rcu_read_unlock();
}

void rt_wait_with_bottom_halves_off(rt_spinlock_t *rt) {
  local_bh_disable();
  rt_spin_lock(rt);
  rt_spin_unlock(rt);
  local_bh_enable();
}

void rt_wait_with_migration_off(rt_spinlock_t *rt) {
  migrate_disable();
  rt_spin_lock(rt);
  rt_spin_unlock(rt);
  migrate_enable();
}

void nested_rt_wait(rt_spinlock_t *outer, rt_spinlock_t *inner) {
  rt_spin_lock(outer);
  rt_spin_lock(inner);
  rt_spin_unlock(inner);
  rt_spin_unlock(outer);
}

// A balanced leave must clear each forbidden state.
void rt_wait_after_balanced_exits(rt_spinlock_t *rt) {
  preempt_disable();
  preempt_enable();
  irq_enter();
  irq_exit();
  nmi_enter();
  nmi_exit();
  local_irq_disable();
  local_irq_enable();
  rt_spin_lock(rt);
  rt_spin_unlock(rt);
}

void rt_wait_between_irq_save_restore(rt_spinlock_t *rt) {
  unsigned long flags = local_irq_save();
  rt_spin_lock(rt); // rt-warning {{Call to RT lock 'rt_spin_lock' with hard interrupts disabled}}
  rt_spin_unlock(rt);
  local_irq_restore(flags);
  rt_spin_lock(rt);
  rt_spin_unlock(rt);
}

void nested_irq_save_restores_disabled_state(rt_spinlock_t *rt) {
  unsigned long outer = local_irq_save();
  unsigned long inner = local_irq_save();
  local_irq_restore(inner);
  rt_spin_lock(rt); // rt-warning {{Call to RT lock 'rt_spin_lock' with hard interrupts disabled}}
  rt_spin_unlock(rt);
  local_irq_restore(outer);
}

void irq_query_refines_each_path(rt_spinlock_t *rt) {
  if (irqs_disabled()) {
    rt_spin_lock(rt); // rt-warning {{Call to RT lock 'rt_spin_lock' with hard interrupts disabled}}
    rt_spin_unlock(rt);
  } else {
    rt_spin_lock(rt);
    rt_spin_unlock(rt);
  }
}

void preempt_counter_bits_are_balanced(rt_spinlock_t *rt) {
  preempt_count_add(1);
  rt_spin_lock(rt); // rt-warning {{Call to RT lock 'rt_spin_lock' with preemption disabled}}
  rt_spin_unlock(rt);
  preempt_count_sub(1);
  rt_spin_lock(rt);
  rt_spin_unlock(rt);
}

void hardirq_counter_bits_are_balanced(rt_spinlock_t *rt) {
  preempt_count_add(1u << 16);
  rt_spin_lock(rt); // rt-warning {{Call to RT lock 'rt_spin_lock' inside a hard IRQ handler}}
  rt_spin_unlock(rt);
  preempt_count_sub(1u << 16);
  rt_spin_lock(rt);
  rt_spin_unlock(rt);
}

void nmi_counter_bits_are_balanced(rt_spinlock_t *rt) {
  preempt_count_add((1u << 20) | (1u << 16));
  rt_spin_lock(rt); // rt-warning {{Call to RT lock 'rt_spin_lock' inside NMI context}}
  rt_spin_unlock(rt);
  preempt_count_sub((1u << 20) | (1u << 16));
  rt_spin_lock(rt);
  rt_spin_unlock(rt);
}

void rt_bottom_half_counter_is_not_preemption_off(rt_spinlock_t *rt) {
  __local_bh_disable_ip(0, 2u << 8);
  rt_spin_lock(rt);
  rt_spin_unlock(rt);
  __local_bh_enable_ip(0, 2u << 8);
}
