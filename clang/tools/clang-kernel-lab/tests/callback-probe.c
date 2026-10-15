extern void irq_enter_rcu(void);
extern int spin_trylock(void);

int probe(int value) {
  irq_enter_rcu();
  if (spin_trylock())
    return value + 1;
  return value;
}
