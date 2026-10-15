#include "fixture-context.h"
extern void p3_rt_wait_effect(void);
/* Separate definition with the same spelling, in another TU. */
static void p3_same_entry(void) { p3_rt_wait_effect(); }
