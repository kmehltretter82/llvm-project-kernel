__attribute__((noinline)) int reschedule_check(int value) {
  return value + 3;
}

volatile int published_irq_state;

__attribute__((noinline)) int irq_map_probe(int value) {
  int published = reschedule_check(value);
  published_irq_state = published;
  return published ^ 1;
}
