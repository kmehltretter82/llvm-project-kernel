// RUN: rm -rf %t && mkdir %t
// RUN: %clang_analyze_cc1 -triple riscv64-unknown-linux-gnu \
// RUN:   -D CONFIG_PREEMPT_RT=1 \
// RUN:   -analyzer-checker=core,alpha.linux.AtomicSleep \
// RUN:   -analyze-function=manifest_identity_anchor \
// RUN:   -analyzer-config alpha.linux.AtomicSleep:RTContext=true \
// RUN:   -analyzer-config alpha.linux.AtomicSleep:RTContextManifestOutput=%t/facts.json \
// RUN:   %s
// RUN: %python %S/Inputs/linux-rt-context-manifest.py \
// RUN:   %t/facts.json %S/Inputs/linux-rt-context-review.txt %t/manifest.json
// RUN: %clang_analyze_cc1 -triple riscv64-unknown-linux-gnu \
// RUN:   -D CONFIG_PREEMPT_RT=1 \
// RUN:   -analyzer-checker=core,alpha.linux.AtomicSleep \
// RUN:   -analyzer-config alpha.linux.AtomicSleep:RTContext=true \
// RUN:   -analyzer-config alpha.linux.AtomicSleep:RTContextManifest=%t/manifest.json \
// RUN:   -verify=manifest %s
// RUN: %clang_analyze_cc1 -triple riscv64-unknown-linux-gnu \
// RUN:   -D CONFIG_PREEMPT_RT=1 \
// RUN:   -analyzer-checker=core,alpha.linux.AtomicSleep \
// RUN:   -analyze-function=manifest_unlisted_external_then_wait \
// RUN:   -analyzer-config alpha.linux.AtomicSleep:RTContext=true \
// RUN:   -verify=default %s
// REQUIRES: riscv-registered-target
// default-no-diagnostics

typedef struct rt_spinlock { int v; } rt_spinlock_t;

void rt_spin_lock(rt_spinlock_t *lock);
void rt_spin_unlock(rt_spinlock_t *lock);
void imported_rt_wait(void);
void imported_sleep(void);
void imported_unknown(void);
void unlisted_external(void);
void __local_bh_enable_ip(unsigned long ip, unsigned int count);
void nmi_exit(void);
void preempt_count_sub(int value);

void manifest_identity_anchor(void) {}

void manifest_hardirq_primitive(rt_spinlock_t *lock) {
  rt_spin_lock(lock); // manifest-warning {{Call to RT lock 'rt_spin_lock' inside a hard IRQ handler}}
  rt_spin_unlock(lock);
}

void manifest_task_effect(void) {
  imported_rt_wait(); // manifest-warning {{Imported effect has no proved post-call context preservation}}
}

void manifest_hardirq_effect(void) {
  imported_rt_wait(); // manifest-warning {{Imported RT lock wait in 'imported_rt_wait' inside a hard IRQ handler}}
                      // manifest-warning@-1 {{Imported effect has no proved post-call context preservation}}
}

void manifest_hardirq_sleep(void) {
  imported_sleep(); // manifest-warning {{Imported sleeping effect in 'imported_sleep' inside a hard IRQ handler}}
                    // manifest-warning@-1 {{Imported effect has no proved post-call context preservation}}
}

void manifest_unknown_effect(void) {
  imported_unknown(); // manifest-warning {{Imported effect has no proved post-call context preservation}}
}

// RCU and softirq context permit the RT-only wait, but the effect record does
// not prove that the callee preserves the caller's context after returning.
void manifest_rcu_effect(void) {
  imported_rt_wait(); // manifest-warning {{Imported effect has no proved post-call context preservation}}
}

void manifest_softirq_effect(void) {
  imported_rt_wait(); // manifest-warning {{Imported effect has no proved post-call context preservation}}
}

void manifest_unlisted_external_then_wait(void) {
  unlisted_external(); // manifest-warning {{Imported entry context became unknown after unmodeled call}}
  imported_rt_wait(); // manifest-warning {{Imported effect has no proved post-call context preservation}}
}

void manifest_callback_then_wait(void (*callback)(void)) {
  callback(); // manifest-warning {{Imported entry context became unknown after unresolved call}}
  imported_rt_wait(); // manifest-warning {{Imported effect has no proved post-call context preservation}}
}

void manifest_bh_exit_balanced(rt_spinlock_t *lock) {
  __local_bh_enable_ip(0, 2u << 8);
  rt_spin_lock(lock);
  rt_spin_unlock(lock);
}

void manifest_softirq_bh_exit_balanced(rt_spinlock_t *lock) {
  __local_bh_enable_ip(0, 2u << 8);
  __local_bh_enable_ip(0, 1u << 8);
  rt_spin_lock(lock);
  rt_spin_unlock(lock);
}

void manifest_nmi_exit_balanced(rt_spinlock_t *lock) {
  nmi_exit();
  rt_spin_lock(lock);
  rt_spin_unlock(lock);
}

void manifest_nmi_counter_exit_balanced(rt_spinlock_t *lock) {
  preempt_count_sub((1u << 20) | (1u << 16));
  rt_spin_lock(lock);
  rt_spin_unlock(lock);
}
