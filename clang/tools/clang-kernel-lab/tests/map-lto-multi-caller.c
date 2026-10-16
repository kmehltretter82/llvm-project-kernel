__attribute__((visibility("hidden"))) int lto_publish(int value);

int lto_multi_irq_entry(int value) {
  return lto_publish(value) + lto_publish(value + 1);
}
