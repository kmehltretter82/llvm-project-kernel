// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -ftrivial-auto-var-init=uninitialized -DG_DISABLE_CHECKS \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableInitializedByteTracking=true \
// RUN:   -verify %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -ftrivial-auto-var-init=uninitialized -DG_DISABLE_CHECKS \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableInitializedByteTracking=true \
// RUN:   -verify %s

typedef __SIZE_TYPE__ size_t;
typedef __INTPTR_TYPE__ ssize_t;
typedef __INT64_TYPE__ int64_t;
typedef __UINT8_TYPE__ uint8_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef uint64_t hwaddr;
typedef uint64_t dma_addr_t;

typedef struct QEMUFile QEMUFile;
typedef struct _GInputStream GInputStream;
typedef struct _GCancellable GCancellable;
typedef struct _GError GError;
typedef struct NetClientState NetClientState;
typedef struct AddressSpace AddressSpace;
typedef struct PCIDevice PCIDevice;
typedef struct BdrvChild BdrvChild;
typedef struct QEMUIOVector {
  size_t size;
} QEMUIOVector;
typedef struct USBEndpoint {
  uint8_t type;
} USBEndpoint;
typedef struct USBCombinedPacket {
  QEMUIOVector iov;
} USBCombinedPacket;
typedef struct USBPacket {
  int pid;
  USBEndpoint *ep;
  QEMUIOVector iov;
  uint64_t parameter;
  int status;
  int actual_length;
  USBCombinedPacket *combined;
} USBPacket;
typedef struct MemTxAttrs {
  unsigned int unspecified : 1;
} MemTxAttrs;
typedef int gboolean;
typedef uint32_t MemTxResult;

size_t qemu_get_buffer(QEMUFile *, unsigned char *, size_t);
unsigned qemu_get_byte(QEMUFile *);
void qemu_put_buffer(QEMUFile *, const unsigned char *, size_t);
gboolean g_input_stream_read_all(GInputStream *, void *, size_t, size_t *,
                                 GCancellable *, GError **);
void error_report(const char *, ...);
void mutate_buffer(unsigned char *);
void trace_dbus_vmstate_loading(const char *);
void *g_hash_table_lookup(void *, const void *);
ssize_t qemu_send_packet(NetClientState *, const unsigned char *, int);
MemTxResult dma_memory_write(AddressSpace *, dma_addr_t, const void *,
                             dma_addr_t, MemTxAttrs);
MemTxResult address_space_write(const AddressSpace *, hwaddr, MemTxAttrs,
                                const void *, hwaddr);
MemTxResult pci_dma_write(PCIDevice *, uint64_t, const void *, uint64_t);
void physical_memory_write(uint64_t, const void *, uint64_t);
int bdrv_pwrite(BdrvChild *, int64_t, int64_t, const void *, int);
void usb_packet_copy(USBPacket *, void *, size_t);

#define USB_TOKEN_SETUP 0x2d
#define USB_TOKEN_IN 0x69
#define USB_TOKEN_OUT 0xe1

void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
size_t strxfrm(char *, const char *, size_t);

static const unsigned char initialized_global[8] = {1, 2, 3, 4,
                                                    5, 6, 7, 8};

#ifdef G_DISABLE_CHECKS
#define g_return_val_if_fail(condition, value) ((void)0)
#else
#define g_return_val_if_fail(condition, value)                              \
  do {                                                                      \
    if (!(condition))                                                       \
      return (value);                                                       \
  } while (0)
#endif

void qemu_get_known_short_bad(QEMUFile *input, QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  qemu_put_buffer(output, buffer, sizeof(buffer));
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void qemu_get_maybe_short_bad(QEMUFile *input, QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  (void)bytes;
  qemu_put_buffer(output, buffer, sizeof(buffer));
  // expected-warning@-1 {{Level B: host-read length may exceed the initialized byte prefix}}
}

void qemu_get_returned_count_good(QEMUFile *input, QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  qemu_put_buffer(output, buffer, bytes);
}

void qemu_get_full_guard_good(QEMUFile *input, QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != sizeof(buffer))
    return;
  qemu_put_buffer(output, buffer, sizeof(buffer));
}

int dbus_vmstate_parent_shape(GInputStream *input, void *proxies,
                              size_t length) {
  unsigned char id[256];
  size_t bytes_read = 0;

  if (length >= sizeof(id))
    return -1;

  if (!g_input_stream_read_all(input, id, length, &bytes_read, 0, 0))
    return -1;
  g_return_val_if_fail(bytes_read == length, -1);
  id[length] = 0;
  trace_dbus_vmstate_loading((const char *)id);
  // expected-warning@-1 {{Level B: C string read may reach bytes beyond the initialized byte prefix}}
  if (!g_hash_table_lookup(proxies, id))
    error_report("%s: Failed to find proxy Id '%s'", __func__, id);
  return 0;
}

int dbus_vmstate_explicit_guard_good(GInputStream *input, size_t length) {
  unsigned char id[256];
  size_t bytes_read = 0;

  if (length >= sizeof(id))
    return -1;

  if (!g_input_stream_read_all(input, id, length, &bytes_read, 0, 0))
    return -1;
  if (bytes_read != length)
    return -1;
  id[length] = 0;
  trace_dbus_vmstate_loading((const char *)id);
  return 0;
}

int dbus_vmstate_error_format_shape(GInputStream *input, size_t length) {
  unsigned char id[256];
  size_t bytes_read = 0;

  if (length >= sizeof(id))
    return -1;
  if (!g_input_stream_read_all(input, id, length, &bytes_read, 0, 0))
    return -1;
  id[length] = 0;
  error_report("%s: Failed to find proxy Id '%s'", __func__, id);
  // expected-warning@-1 {{Level B: C string read may reach bytes beyond the initialized byte prefix}}
  return 0;
}

void bounded_constant_precision_string_good(QEMUFile *input) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  error_report("%.4s", (const char *)buffer);
}

void bounded_star_precision_string_good(QEMUFile *input) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  error_report("%.*s", 4, (const char *)buffer);
}

void input_stream_returned_count_good(GInputStream *input, QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes_read = 0;

  if (!g_input_stream_read_all(input, buffer, sizeof(buffer), &bytes_read, 0,
                               0))
    return;
  qemu_put_buffer(output, buffer, bytes_read);
}

void input_stream_failure_preserves_partial_count(GInputStream *input,
                                                  QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes_read = 0;

  if (g_input_stream_read_all(input, buffer, sizeof(buffer), &bytes_read, 0,
                              0))
    return;
  // The public contract does not say that FALSE makes bytes_read strictly
  // smaller than the request, so a complete read remains feasible here.
  qemu_put_buffer(output, buffer, sizeof(buffer));
  // expected-warning@-1 {{Level B: host-read length may exceed the initialized byte prefix}}
}

void input_stream_missing_count_abandons_precision(GInputStream *input,
                                                   QEMUFile *output) {
  unsigned char buffer[8];

  if (g_input_stream_read_all(input, buffer, sizeof(buffer), 0, 0, 0))
    return;
  qemu_put_buffer(output, buffer, sizeof(buffer));
}

void zero_initializer_preserves_full_prefix(QEMUFile *input,
                                            QEMUFile *output) {
  unsigned char buffer[8] = {0};
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  qemu_put_buffer(output, buffer, sizeof(buffer));
}

void static_local_zero_initializer_preserves_full_prefix(QEMUFile *input,
                                                         QEMUFile *output) {
  static unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  qemu_put_buffer(output, buffer, sizeof(buffer));
}

void declaration_reentry_clears_prior_ranges(QEMUFile *output) {
  for (int iteration = 0; iteration < 2; ++iteration) {
    unsigned char buffer[8];
    if (iteration == 0) {
      memset(buffer, 0, sizeof(buffer));
      continue;
    }
    qemu_put_buffer(output, buffer, sizeof(buffer));
    // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
  }
}

void full_memset_preserves_full_prefix(QEMUFile *input, QEMUFile *output) {
  unsigned char buffer[8];
  memset(buffer, 0, sizeof(buffer));
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  qemu_put_buffer(output, buffer, sizeof(buffer));
}

void partial_copy_propagates_prefix_bad(QEMUFile *input, QEMUFile *output) {
  unsigned char source[8];
  unsigned char destination[8];
  size_t bytes = qemu_get_buffer(input, source, sizeof(source));
  if (bytes != 4)
    return;
  memcpy(destination, source, bytes);
  qemu_put_buffer(output, destination, sizeof(destination));
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void full_memmove_propagates_prefix_good(QEMUFile *input,
                                         QEMUFile *output) {
  unsigned char source[8];
  unsigned char destination[8];
  size_t bytes = qemu_get_buffer(input, source, sizeof(source));
  if (bytes != sizeof(source))
    return;
  memmove(destination, source, sizeof(source));
  qemu_put_buffer(output, destination, sizeof(destination));
}

void memcpy_reads_beyond_prefix_bad(QEMUFile *input) {
  unsigned char source[8];
  unsigned char destination[8];
  size_t bytes = qemu_get_buffer(input, source, sizeof(source));
  if (bytes != 4)
    return;
  memcpy(destination, source, sizeof(source));
  qemu_put_buffer(input, destination, sizeof(destination));
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void later_full_copy_repairs_prefix(QEMUFile *input, QEMUFile *output) {
  unsigned char complete[8] = {0};
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  memcpy(buffer, complete, sizeof(buffer));
  qemu_put_buffer(output, buffer, sizeof(buffer));
}

void contiguous_byte_write_extends_prefix(QEMUFile *input,
                                          QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  buffer[4] = 0;
  qemu_put_buffer(output, buffer, 5);
}

void symbolic_terminator_extends_prefix_for_fixed_read(QEMUFile *input,
                                                        QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer) - 1);
  if (bytes >= sizeof(buffer))
    return;
  buffer[bytes] = 0;
  qemu_put_buffer(output, buffer, bytes + 1);
}

void gapped_byte_write_does_not_extend_prefix(QEMUFile *input,
                                              QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  buffer[6] = 0;
  qemu_put_buffer(output, buffer, 7);
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void scalar_store_initializes_full_width(QEMUFile *output) {
  _Alignas(uint32_t) unsigned char buffer[8];
  *(uint32_t *)buffer = 0x01010101U;
  qemu_put_buffer(output, buffer, sizeof(uint32_t));
}

void scalar_store_invalidates_overwritten_terminator(QEMUFile *input) {
  _Alignas(uint32_t) unsigned char buffer[12];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  buffer[6] = 0;
  *(uint32_t *)&buffer[4] = 0x01010101U;
  buffer[10] = 0;
  trace_dbus_vmstate_loading((const char *)buffer);
  // expected-warning@-1 {{Level B: C string read may reach bytes beyond the initialized byte prefix}}
}

void fixed_offset_sink_within_prefix_good(QEMUFile *input,
                                          QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  qemu_put_buffer(output, &buffer[2], 2);
}

void fixed_offset_sink_crosses_prefix_bad(QEMUFile *input,
                                          QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  qemu_put_buffer(output, &buffer[2], 3);
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void sink_strictly_after_prefix_uses_initialized_interval(QEMUFile *input,
                                                         QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  buffer[6] = 0;
  qemu_put_buffer(output, &buffer[6], 1);
}

void gap_then_full_bridge_is_clean(QEMUFile *input, QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  buffer[6] = 0;
  buffer[4] = 0;
  buffer[5] = 0;
  qemu_put_buffer(output, buffer, 7);
}

void zero_element_alias_is_tracked(QEMUFile *input, QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, &buffer[0], sizeof(buffer));
  if (bytes != 4)
    return;
  qemu_put_buffer(output, &buffer[0], sizeof(buffer));
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void unknown_mutation_drops_affected_fact(QEMUFile *input,
                                          QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  mutate_buffer(buffer);
  qemu_put_buffer(output, buffer, sizeof(buffer));
}

void noncall_invalidation_drops_affected_fact(QEMUFile *input,
                                              QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  __asm__ volatile("" : "=m"(buffer));
  qemu_put_buffer(output, buffer, sizeof(buffer));
}

void default_bind_abandons_partial_fact(QEMUFile *input, QEMUFile *output) {
  unsigned char destination[8];
  const char source[] = "x";
  size_t bytes =
      qemu_get_buffer(input, destination, sizeof(destination));
  if (bytes != 4)
    return;
  size_t transformed =
      strxfrm((char *)destination, source, sizeof(destination));
  if (transformed < sizeof(destination))
    return;
  // CStringModeling binds destination undefined on this failure path.  That
  // default bind must abandon our old four-byte coverage rather than retain
  // it and produce a false initialized-prefix diagnostic here.
  qemu_put_buffer(output, destination, sizeof(destination));
}

void unrelated_mutation_preserves_fact(QEMUFile *input, QEMUFile *output) {
  unsigned char buffer[8];
  unsigned char unrelated[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  mutate_buffer(unrelated);
  qemu_put_buffer(output, buffer, sizeof(buffer));
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void shorter_later_read_does_not_shrink_prefix(QEMUFile *input,
                                               QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != sizeof(buffer))
    return;
  bytes = qemu_get_buffer(input, buffer, 4);
  if (bytes != 2)
    return;
  qemu_put_buffer(output, buffer, sizeof(buffer));
}

void shifted_read_bad(QEMUFile *input, QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, &buffer[1], sizeof(buffer) - 1);
  if (bytes != 3)
    return;
  qemu_put_buffer(output, &buffer[1], sizeof(buffer) - 1);
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void shifted_copy_bad(QEMUFile *input, QEMUFile *output) {
  unsigned char source[8];
  unsigned char destination[8];
  size_t bytes = qemu_get_buffer(input, source, sizeof(source));
  if (bytes != 4)
    return;
  memcpy(&destination[1], &source[1], 3);
  qemu_put_buffer(output, destination, sizeof(destination));
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void symbolic_offset_bad(QEMUFile *input, QEMUFile *output, size_t offset) {
  unsigned char buffer[8];
  if (offset >= sizeof(buffer))
    return;
  size_t bytes =
      qemu_get_buffer(input, &buffer[offset], sizeof(buffer) - offset);
  if (bytes != 1)
    return;
  qemu_put_buffer(output, &buffer[offset], sizeof(buffer) - offset);
  // expected-warning@-1 {{Level B: host-read length may exceed the initialized byte prefix}}
}

void initialized_destination_suffix_survives_copy(QEMUFile *input,
                                                   QEMUFile *output) {
  unsigned char source[8];
  unsigned char destination[8] = {0};
  size_t bytes = qemu_get_buffer(input, source, sizeof(source));
  if (bytes != 4)
    return;
  memcpy(destination, source, bytes);
  qemu_put_buffer(output, destination, sizeof(destination));
}

void uninitialized_copy_overwrites_destination(QEMUFile *output) {
  unsigned char source[8];
  unsigned char destination[8] = {0};
  memcpy(destination, source, 4);
  qemu_put_buffer(output, destination, sizeof(destination));
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void opaque_copy_source_abandons_precision(QEMUFile *output,
                                           const unsigned char *source) {
  unsigned char destination[8] = {0};
  memcpy(destination, source, 4);
  qemu_put_buffer(output, destination, sizeof(destination));
}

void static_source_copy_good(QEMUFile *output) {
  unsigned char destination[8];
  memcpy(destination, initialized_global, sizeof(destination));
  qemu_put_buffer(output, destination, sizeof(destination));
}

void static_interior_source_is_not_overestimated(QEMUFile *output) {
  unsigned char destination[8];
  memcpy(destination, &initialized_global[4], 4);
  qemu_put_buffer(output, destination, 5);
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void overlapping_memmove_good(QEMUFile *output) {
  unsigned char buffer[8] = {0};
  memmove(&buffer[1], buffer, 7);
  qemu_put_buffer(output, buffer, sizeof(buffer));
}

void adjacent_symbolic_range_good(QEMUFile *input, QEMUFile *output) {
  unsigned char buffer[8];
  size_t head = qemu_get_buffer(input, buffer, 4);
  if (head != 4)
    return;
  size_t tail = qemu_get_buffer(input, &buffer[4], 4);
  qemu_put_buffer(output, &buffer[4], tail);
}

void many_adjacent_writes_remain_exact(QEMUFile *output) {
  unsigned char buffer[16];
  buffer[0] = 1;
  buffer[1] = 1;
  buffer[2] = 1;
  buffer[3] = 1;
  buffer[4] = 1;
  buffer[5] = 1;
  buffer[6] = 1;
  buffer[7] = 1;
  buffer[8] = 1;
  buffer[9] = 1;
  buffer[10] = 1;
  buffer[11] = 1;
  qemu_put_buffer(output, buffer, 13);
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void interval_cap_abandons_without_warning(QEMUFile *output) {
  unsigned char buffer[32];
  buffer[0] = 1;
  buffer[2] = 1;
  buffer[4] = 1;
  buffer[6] = 1;
  buffer[8] = 1;
  buffer[10] = 1;
  buffer[12] = 1;
  buffer[14] = 1;
  buffer[16] = 1;
  qemu_put_buffer(output, buffer, sizeof(buffer));
}

void full_memset_restores_after_interval_cap(QEMUFile *output) {
  unsigned char buffer[32];
  buffer[0] = 1;
  buffer[2] = 1;
  buffer[4] = 1;
  buffer[6] = 1;
  buffer[8] = 1;
  buffer[10] = 1;
  buffer[12] = 1;
  buffer[14] = 1;
  buffer[16] = 1;
  memset(buffer, 0, sizeof(buffer));
  qemu_put_buffer(output, buffer, sizeof(buffer));
}

void network_sink_bad(QEMUFile *input, NetClientState *nc) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  qemu_send_packet(nc, buffer, sizeof(buffer));
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void dma_sink_bad(QEMUFile *input, AddressSpace *as) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  dma_memory_write(as, 0, buffer, sizeof(buffer), (MemTxAttrs){0});
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void address_space_sink_bad(QEMUFile *input, AddressSpace *as) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  address_space_write(as, 0, (MemTxAttrs){0}, buffer, sizeof(buffer));
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void pci_dma_sink_bad(QEMUFile *input, PCIDevice *dev) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  pci_dma_write(dev, 0, buffer, sizeof(buffer));
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void physical_dma_sink_bad(QEMUFile *input) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  physical_memory_write(0, buffer, sizeof(buffer));
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void block_sink_bad(QEMUFile *input, BdrvChild *child) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  bdrv_pwrite(child, 0, sizeof(buffer), buffer, 0);
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void usb_in_sink_bad(QEMUFile *input, USBPacket *packet) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  packet->pid = USB_TOKEN_IN;
  usb_packet_copy(packet, buffer, sizeof(buffer));
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void usb_in_returned_count_good(QEMUFile *input, USBPacket *packet) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  packet->pid = USB_TOKEN_IN;
  usb_packet_copy(packet, buffer, bytes);
}

void usb_out_initializes_exact_range(QEMUFile *output, USBPacket *packet) {
  unsigned char buffer[8];
  USBEndpoint endpoint;
  endpoint.type = 2;
  packet->pid = USB_TOKEN_OUT;
  packet->ep = &endpoint;
  packet->iov.size = sizeof(buffer);
  packet->parameter = 0;
  packet->status = 0;
  packet->actual_length = 0;
  packet->combined = 0;
  usb_packet_copy(packet, buffer, 4);
  qemu_put_buffer(output, buffer, 4);
  qemu_put_buffer(output, buffer, sizeof(buffer));
  // expected-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void usb_setup_initializes_full_object(QEMUFile *output, USBPacket *packet) {
  unsigned char buffer[8];
  USBEndpoint endpoint;
  USBCombinedPacket combined;
  endpoint.type = 0;
  combined.iov.size = sizeof(buffer);
  packet->pid = USB_TOKEN_SETUP;
  packet->ep = &endpoint;
  packet->iov.size = 1;
  packet->parameter = (uint64_t)sizeof(buffer) << 48;
  packet->status = 0;
  packet->actual_length = 0;
  packet->combined = &combined;
  usb_packet_copy(packet, buffer, sizeof(buffer));
  qemu_put_buffer(output, buffer, sizeof(buffer));
}

void usb_unknown_direction_is_conservative(QEMUFile *output,
                                           USBPacket *packet, int pid) {
  unsigned char buffer[8];
  packet->pid = pid;
  usb_packet_copy(packet, buffer, sizeof(buffer));
  qemu_put_buffer(output, buffer, sizeof(buffer));
}

void usb_unknown_direction_still_checks_bounds(QEMUFile *input,
                                               QEMUFile *output,
                                               USBPacket *packet, int pid) {
  unsigned char buffer[8];
  packet->pid = pid;
  size_t length = qemu_get_byte(input);
  usb_packet_copy(packet, buffer, length);
  // expected-warning@-1 {{Level B: guest-controlled USB packet buffer length may exceed the host object extent}}
  // An unresolved direction must not claim that the safe-path copy initialized
  // or disclosed the buffer.  Abandoning its byte precision avoids a second
  // diagnostic here.
  qemu_put_buffer(output, buffer, sizeof(buffer));
}

void usb_in_direction_does_not_leak_across_loop(QEMUFile *input,
                                                QEMUFile *output,
                                                USBPacket *packet, int pid) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  for (int iteration = 0; iteration != 2; ++iteration) {
    packet->pid = iteration == 0 ? USB_TOKEN_IN : pid;
    // The same CallExpr is revisited.  The first IN direction must be removed
    // before the unresolved second iteration, which abandons buffer precision.
    usb_packet_copy(packet, buffer, 0);
  }
  qemu_put_buffer(output, buffer, sizeof(buffer));
}
