/* Independent importer fixture proposal; never built or executed by review. */
void ordinary_effect_decl(void);
void rt_wait_effect_decl(void);
void effect_with_pointer(const unsigned long *);
void _raw_spin_lock(void *);
void _raw_spin_unlock(void *);
void local_irq_disable(void);
void local_irq_enable(void);
void preempt_disable(void);
void preempt_enable(void);
void local_bh_disable(void);
void local_bh_enable(void);
void rcu_read_lock(void);
void rcu_read_unlock(void);
void migrate_disable(void);
void migrate_enable(void);
void opaque_unlock_helper(void);

void nested_seed_enabled(void)
{
    ordinary_effect_decl();
}

void explicit_disable_then_nested(void)
{
    local_irq_disable();
    nested_seed_enabled();
    local_irq_enable();
}

void raw_context_effects(void *lock)
{
    _raw_spin_lock(lock);
    ordinary_effect_decl();
    rt_wait_effect_decl();
    _raw_spin_unlock(lock);
}

void preempt_context_effects(void)
{
    preempt_disable();
    ordinary_effect_decl();
    rt_wait_effect_decl();
    preempt_enable();
}

void bh_context_effects(void)
{
    local_bh_disable();
    ordinary_effect_decl();
    rt_wait_effect_decl();
    local_bh_enable();
}

void rcu_context_effects(void)
{
    rcu_read_lock();
    ordinary_effect_decl();
    rt_wait_effect_decl();
    rcu_read_unlock();
}

void migration_context_effects(void)
{
    migrate_disable();
    ordinary_effect_decl();
    rt_wait_effect_decl();
    migrate_enable();
}

void resolved_function_pointer(void)
{
    void (*fp)(void) = ordinary_effect_decl;
    local_irq_disable();
    fp();
    local_irq_enable();
}

void unresolved_function_pointer(void (*ordinary_effect_decl)(void))
{
    local_irq_disable();
    ordinary_effect_decl();
    local_irq_enable();
}

void imported_effect_then_opaque(void *lock)
{
    _raw_spin_lock(lock);
    ordinary_effect_decl();
    opaque_unlock_helper();
    ordinary_effect_decl();
}

/* Canonical declaration precedes the body in the same file for key tests. */
void prototype_then_body(void);
void prototype_then_body(void)
{
    ordinary_effect_decl();
}

static void static_identity(void)
{
    ordinary_effect_decl();
}

void call_static_identity(void)
{
    local_irq_disable();
    static_identity();
    local_irq_enable();
}
