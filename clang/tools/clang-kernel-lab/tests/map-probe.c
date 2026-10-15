__attribute__((noinline)) int publish_irq_state(int value) {
  return value + 3;
}

volatile int published_irq_state;

__attribute__((noinline)) int irq_map_probe(int value) {
  int published = publish_irq_state(value);
  published_irq_state = published;
  return published ^ 1;
}
