// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.LockContext \
// RUN:   -analyzer-config ipa=none -analyzer-output=text -verify %s

typedef void RCUReadAuto;
typedef struct BQLLockAuto BQLLockAuto;

void rcu_read_lock(void);
void rcu_read_unlock(void);
RCUReadAuto *rcu_read_auto_lock(void);
void rcu_read_auto_unlock(RCUReadAuto *guard);
void glib_autoptr_cleanup_RCUReadAuto(RCUReadAuto **guard);
void synchronize_rcu(void);
void drain_call_rcu(void);
void rcu_unregister_thread(void);

void bql_lock_impl(const char *file, int line);
void bql_unlock(void);
BQLLockAuto *bql_auto_lock(const char *file, int line);
void bql_auto_unlock(BQLLockAuto *guard);
void glib_autoptr_cleanup_BQLLockAuto(BQLLockAuto **guard);
void qemu_cond_wait_bql(void *cond);
void bdrv_graph_wrlock(void);
int qemu_in_coroutine(void);

#define RCU_GUARD()                                                          \
  RCUReadAuto *guard __attribute__((cleanup(                                \
      glib_autoptr_cleanup_RCUReadAuto))) = rcu_read_auto_lock()
#define BQL_GUARD()                                                          \
  BQLLockAuto *guard __attribute__((cleanup(                                \
      glib_autoptr_cleanup_BQLLockAuto))) = bql_auto_lock(__FILE__, __LINE__)

void balanced_rcu(void) {
  rcu_read_lock();
  rcu_read_unlock();
}

void nested_rcu_is_valid(void) {
  rcu_read_lock();
  rcu_read_lock();
  rcu_read_unlock();
  rcu_read_unlock();
}

void leaked_rcu(int early) {
  rcu_read_lock(); // expected-note {{RCU read-side critical section entered here}}
  if (early)       // expected-note {{Assuming 'early' is not equal to 0}}
                   // expected-note@-1 {{Taking true branch}}
    return; // expected-warning {{QEMU RCU read-side critical section is not exited on this path}}
            // expected-note@-1 {{QEMU RCU read-side critical section is not exited on this path}}
  rcu_read_unlock();
}

void grace_period_inside_rcu(void) {
  rcu_read_lock(); // expected-note {{RCU read-side critical section entered here}}
  synchronize_rcu(); // expected-warning {{RCU grace-period wait is called inside a QEMU RCU read-side critical section}}
                     // expected-note@-1 {{RCU grace-period wait is called inside a QEMU RCU read-side critical section}}
  rcu_read_unlock();
}

void unregister_inside_rcu(void) {
  rcu_read_lock(); // expected-note {{RCU read-side critical section entered here}}
  rcu_unregister_thread(); // expected-warning {{RCU thread is unregistered inside a QEMU RCU read-side critical section}}
                           // expected-note@-1 {{RCU thread is unregistered inside a QEMU RCU read-side critical section}}
  rcu_read_unlock();
}

void cleanup_rcu_guard_is_balanced(void) {
  RCU_GUARD();
}

void balanced_bql(void) {
  bql_lock_impl(__FILE__, __LINE__);
  bql_unlock();
}

void leaked_bql(void) {
  bql_lock_impl(__FILE__, __LINE__); // expected-warning {{BQL acquired in this function is not released on this path}}
                                    // expected-note@-1 {{BQL acquired here}}
                                    // expected-note@-2 {{BQL acquired in this function is not released on this path}}
}

void double_bql_lock(void) {
  bql_lock_impl(__FILE__, __LINE__); // expected-note {{BQL acquired here}}
  bql_lock_impl(__FILE__, __LINE__); // expected-warning {{BQL is acquired again while already held}}
                                    // expected-note@-1 {{BQL is acquired again while already held}}
  bql_unlock();
}

void double_bql_unlock(void) {
  bql_unlock();
  bql_unlock(); // expected-warning {{BQL is released again after it was already released}}
                // expected-note@-1 {{BQL is released again after it was already released}}
}

void inherited_bql_unlock_and_relock(void) {
  bql_unlock();
  bql_lock_impl(__FILE__, __LINE__);
}

void repeated_coroutine_queries_are_stable(void) {
  if (qemu_in_coroutine()) {
    if (!qemu_in_coroutine())
      bql_unlock();
    if (!qemu_in_coroutine())
      bql_lock_impl(__FILE__, __LINE__);
  }
}

void graph_lock_after_bql_release(void) {
  bql_unlock();
  bdrv_graph_wrlock(); // expected-warning {{Call to 'bdrv_graph_wrlock' requires the BQL after this path released it}}
                       // expected-note@-1 {{Call to 'bdrv_graph_wrlock' requires the BQL after this path released it}}
}

void wait_after_bql_release(void *cond) {
  bql_unlock();
  qemu_cond_wait_bql(cond); // expected-warning {{Call to 'qemu_cond_wait_bql' requires the BQL after this path released it}}
                            // expected-note@-1 {{Call to 'qemu_cond_wait_bql' requires the BQL after this path released it}}
}

void cleanup_bql_guard_is_balanced(void) {
  BQL_GUARD();
}

void qemu_log_trylock_with_err(void) { rcu_read_lock(); }

void prepare_mmio_access(void) { bql_lock_impl(__FILE__, __LINE__); }

void qemu_init_subsystems(void) { bql_lock_impl(__FILE__, __LINE__); }

__attribute__((annotate("qemu::returns_with_rcu_read_lock"))) void
annotated_rcu_handoff(void) {
  rcu_read_lock();
}

__attribute__((annotate("qemu::returns_with_bql"))) void
annotated_bql_handoff(void) {
  bql_lock_impl(__FILE__, __LINE__);
}

void indirect_operations_are_unmodeled(void (*lock)(void),
                                       void (*unlock)(void)) {
  lock();
  unlock();
}

__attribute__((suppress)) void explicitly_suppressed_leak(void) {
  rcu_read_lock();
}
