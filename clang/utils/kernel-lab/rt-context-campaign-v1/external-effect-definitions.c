/* Review evidence only; this TU is not linked or analyzed during importer tests.
 * The declared effects in the oracle are independently reviewed API contracts.
 */
#include "fixture-context.h"
extern void rt_spin_lock(spinlock_t *);
extern void rt_spin_unlock(spinlock_t *);
extern void schedule(void);
extern void foreign_context_action(void);
void p3_rt_wait_effect(void) {
  spinlock_t lock;
  rt_spin_lock(&lock);
  rt_spin_unlock(&lock);
}
void p3_ordinary_sleep_effect(void) { schedule(); }
void p3_opaque_effect(void) { foreign_context_action(); }
