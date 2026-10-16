__attribute__((visibility("hidden"))) volatile int lto_published_irq_state;

__attribute__((visibility("hidden"))) int lto_publish(int value) {
#ifdef KERNEL_LAB_SOURCE_SITE
  __builtin_riscv_linux_irq_site(39, 0);
#endif
  lto_published_irq_state = value;
  return value + 1;
}
