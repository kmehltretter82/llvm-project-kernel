__attribute__((noinline)) int reschedule_check(int value) {
  return value + 3;
}

volatile int published_irq_state;

__attribute__((used, noinline, section(".noinstr.text"))) int
noinstr_map_probe(int value) {
  return value - 1;
}

__attribute__((noinline)) int irq_map_probe(int value) {
  int published = reschedule_check(value);
#ifdef KERNEL_LAB_SOURCE_SITE
  __builtin_riscv_linux_irq_site(39, 0);
#endif
  published_irq_state = published;
  return published ^ 1;
}
