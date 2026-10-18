// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety -analyzer-output=text -verify %s

typedef __SIZE_TYPE__ size_t;
typedef __UINT8_TYPE__ uint8_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;

typedef struct VirtIODevice VirtIODevice;
typedef struct PCIDevice PCIDevice;
typedef struct NetClientState NetClientState;
typedef struct NetFilterState NetFilterState;
typedef struct SCSIDevice SCSIDevice;
typedef struct SCSICommand SCSICommand;
typedef struct SCSIRequest SCSIRequest;
typedef void NetPacketSent(NetClientState *, long);

struct VirtIODevice {
  size_t config_len;
};

void *memcpy(void *, const void *, size_t);

struct SCSICommand {
  uint8_t buf[16];
  int len;
};

struct SCSIRequest {
  SCSICommand cmd;
};

struct iovec {
  void *iov_base;
  size_t iov_len;
};

typedef struct VirtioDeviceClass {
  void (*set_features_ex)(VirtIODevice *, const uint64_t *);
  void (*set_features)(VirtIODevice *, uint64_t);
  void (*set_config)(VirtIODevice *, const uint8_t *);
  int (*set_status)(VirtIODevice *, uint8_t);
  void (*queue_reset)(VirtIODevice *, uint32_t);
  void (*queue_enable)(VirtIODevice *, uint32_t);
} VirtioDeviceClass;

static int callback_result;

static void virtio_set_features(VirtIODevice *vdev, uint64_t features) { // expected-note {{virtio configuration callback parameter 'features' is guest-controlled}}
  int slots[4] = {0};
  callback_result = slots[features]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                      // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void virtio_set_features_ex(VirtIODevice *vdev,
                                   const uint64_t *value) {
  int slots[4] = {0};
  callback_result = slots[value[1]]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                      // expected-note@-1 {{virtio configuration callback parameter 'value' is guest-controlled}}
                                      // expected-note@-2 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void virtio_set_config_direct(VirtIODevice *vdev, const uint8_t *config) { // expected-note {{virtio configuration callback buffer parameter 'config' supplies guest-controlled bytes}}
  callback_result = config[4]; // expected-warning {{Level B: virtio configuration callback buffer read may exceed the available guest-input bytes}}
                               // expected-note@-1 {{Level B: virtio configuration callback buffer read may exceed the available guest-input bytes}}
}

static void virtio_set_config_copy(VirtIODevice *vdev, const uint8_t *config) { // expected-note {{virtio configuration callback buffer parameter 'config' supplies guest-controlled bytes}}
  uint8_t destination[8];
  memcpy(destination, config, sizeof(destination)); // expected-warning {{Level B: virtio configuration callback buffer read may exceed the available guest-input bytes}}
                                                    // expected-note@-1 {{Level B: virtio configuration callback buffer read may exceed the available guest-input bytes}}
}

static void virtio_set_config_alias(VirtIODevice *vdev, const uint8_t *config) { // expected-note {{virtio configuration callback buffer parameter 'config' supplies guest-controlled bytes}}
  const uint8_t *alias = config;
  callback_result = alias[4]; // expected-warning {{Level B: virtio configuration callback buffer read may exceed the available guest-input bytes}}
                              // expected-note@-1 {{Level B: virtio configuration callback buffer read may exceed the available guest-input bytes}}
}

static void virtio_set_config_reassigned( // expected-note {{virtio configuration callback buffer parameter 'config' supplies guest-controlled bytes}}
    VirtIODevice *vdev, const uint8_t *config) {
  const uint8_t *alias = config;
  config = 0;
  callback_result = alias[4]; // expected-warning {{Level B: virtio configuration callback buffer read may exceed the available guest-input bytes}}
                              // expected-note@-1 {{Level B: virtio configuration callback buffer read may exceed the available guest-input bytes}}
}

static uint8_t read_config_byte(const uint8_t *config) {
  return config[4]; // expected-warning {{Level B: virtio configuration callback buffer read may exceed the available guest-input bytes}}
                    // expected-note@-1 {{Level B: virtio configuration callback buffer read may exceed the available guest-input bytes}}
}

static void virtio_set_config_helper(VirtIODevice *vdev, const uint8_t *config) { // expected-note {{virtio configuration callback buffer parameter 'config' supplies guest-controlled bytes}}
  callback_result = read_config_byte(config); // expected-note {{Calling 'read_config_byte'}}
}

static void virtio_set_config_direct_guarded(VirtIODevice *vdev,
                                             const uint8_t *config) {
  if (vdev->config_len <= 4)
    return;
  callback_result = config[4];
}

static void virtio_set_config_copy_guarded(VirtIODevice *vdev,
                                           const uint8_t *config) {
  uint8_t destination[8];
  if (vdev->config_len < sizeof(destination))
    return;
  memcpy(destination, config, sizeof(destination));
}

static int virtio_set_status(VirtIODevice *vdev, uint8_t status) { // expected-note {{virtio configuration callback parameter 'status' is guest-controlled}}
  int slots[4] = {0};
  return slots[status]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                        // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void virtio_queue_reset(VirtIODevice *vdev, uint32_t index) { // expected-note {{virtio configuration callback parameter 'index' is guest-controlled}}
  int queues[4] = {0};
  callback_result = queues[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                   // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void virtio_queue_enable(VirtIODevice *vdev, uint32_t index) { // expected-note {{virtio configuration callback parameter 'index' is guest-controlled}}
  int queues[4] = {0};
  callback_result = queues[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                   // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void virtio_features_guarded(VirtIODevice *vdev, uint64_t features) {
  int slots[4] = {0};
  if (features >= 4)
    return;
  callback_result = slots[features];
}

static void virtio_signature_spoof(VirtIODevice *vdev, uint32_t features) {
  int slots[4] = {0};
  callback_result = slots[features];
}

static void register_virtio_callbacks(VirtioDeviceClass *vdc) {
  vdc->set_features = virtio_set_features;
  vdc->set_features_ex = virtio_set_features_ex;
  vdc->set_status = virtio_set_status;
  vdc->queue_reset = virtio_queue_reset;
  vdc->queue_enable = virtio_queue_enable;
}

static void register_virtio_config_direct_callback(VirtioDeviceClass *vdc) {
  vdc->set_config = virtio_set_config_direct;
}

static void register_virtio_config_copy_callback(VirtioDeviceClass *vdc) {
  vdc->set_config = virtio_set_config_copy;
}

static void register_virtio_config_alias_callback(VirtioDeviceClass *vdc) {
  vdc->set_config = virtio_set_config_alias;
}

static void register_virtio_config_reassigned_callback(VirtioDeviceClass *vdc) {
  vdc->set_config = virtio_set_config_reassigned;
}

static void register_virtio_config_helper_callback(VirtioDeviceClass *vdc) {
  vdc->set_config = virtio_set_config_helper;
}

static void
register_virtio_config_direct_guarded_callback(VirtioDeviceClass *vdc) {
  vdc->set_config = virtio_set_config_direct_guarded;
}

static void
register_virtio_config_copy_guarded_callback(VirtioDeviceClass *vdc) {
  vdc->set_config = virtio_set_config_copy_guarded;
}

static void register_guarded_virtio_callback(VirtioDeviceClass *vdc) {
  vdc->set_features = virtio_features_guarded;
}

static void register_spoofed_virtio_callback(VirtioDeviceClass *vdc) {
  vdc->set_features =
      (void (*)(VirtIODevice *, uint64_t))virtio_signature_spoof;
}

typedef struct PCIDeviceClass {
  void (*config_write)(PCIDevice *, uint32_t, uint32_t, int);
} PCIDeviceClass;

static void pci_config_index(PCIDevice *dev, uint32_t address, // expected-note {{PCI configuration callback parameter 'address' is guest-controlled}}
                             uint32_t data, int length) {
  int config[4] = {0};
  callback_result = config[address]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                     // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void pci_config_guarded(PCIDevice *dev, uint32_t address,
                               uint32_t data, int length) {
  int config[4] = {0};
  if (address >= 4)
    return;
  callback_result = config[address];
}

static void pci_config_signature_spoof(PCIDevice *dev, uint64_t address,
                                       uint32_t data, int length) {
  int config[4] = {0};
  callback_result = config[address];
}

static void register_pci_callbacks(PCIDeviceClass *pc) {
  pc->config_write = pci_config_index;
}

static void register_guarded_pci_callback(PCIDeviceClass *pc) {
  pc->config_write = pci_config_guarded;
}

static void register_spoofed_pci_callback(PCIDeviceClass *pc) {
  pc->config_write = (void (*)(PCIDevice *, uint32_t, uint32_t,
                               int))pci_config_signature_spoof;
}

typedef struct NetClientInfo {
  long (*receive)(NetClientState *, const uint8_t *, size_t);
  long (*receive_iov)(NetClientState *, const struct iovec *, int);
} NetClientInfo;

typedef struct NetFilterClass {
  long (*receive_iov)(NetFilterState *, NetClientState *, unsigned,
                      const struct iovec *, int, NetPacketSent *);
} NetFilterClass;

static long network_iov_count(NetClientState *client, // expected-note {{network receive callback parameter 'iovcnt' is guest-controlled}}
                              const struct iovec *iov, int iovcnt) {
  int slots[4] = {0};
  return slots[(unsigned)iovcnt]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                  // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static long network_iov_count_guarded(NetClientState *client,
                                      const struct iovec *iov, int iovcnt) {
  int slots[4] = {0};
  if (iovcnt < 0 || iovcnt >= 4)
    return 0;
  return slots[iovcnt];
}

static long network_iov_signature_spoof(NetClientState *client,
                                        const void *iov, int iovcnt) {
  int slots[4] = {0};
  return slots[(unsigned)iovcnt];
}

static long netfilter_iov_count(NetFilterState *filter, // expected-note {{network receive callback parameter 'iovcnt' is guest-controlled}}
                                NetClientState *sender, unsigned flags,
                                const struct iovec *iov, int iovcnt,
                                NetPacketSent *sent_cb) {
  int slots[4] = {0};
  return slots[(unsigned)iovcnt]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                  // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static const NetClientInfo network_iov_info = {
    .receive_iov = network_iov_count,
};

static const NetClientInfo guarded_network_iov_info = {
    .receive_iov = network_iov_count_guarded,
};

static const NetClientInfo spoofed_network_iov_info = {
    .receive_iov = (long (*)(NetClientState *, const struct iovec *,
                             int))network_iov_signature_spoof,
};

static void register_netfilter_callback(NetFilterClass *nfc) {
  nfc->receive_iov = netfilter_iov_count;
}

typedef struct SCSIBusInfo {
  int (*parse_cdb)(SCSIDevice *, SCSICommand *, uint8_t *, size_t, void *);
} SCSIBusInfo;

typedef struct SCSIDeviceClass {
  int (*parse_cdb)(SCSIDevice *, SCSICommand *, uint8_t *, size_t, void *);
} SCSIDeviceClass;

typedef struct SCSIReqOps {
  size_t size;
  int (*send_command)(SCSIRequest *, uint8_t *);
} SCSIReqOps;

static int scsi_parse_cdb(SCSIDevice *dev, SCSICommand *command,
                          uint8_t *cdb, size_t cdb_length,
                          void *hba_private) {
  int handlers[4] = {0};
  if (cdb_length < 2) // expected-note {{Assuming 'cdb_length' is >= 2}}
                       // expected-note@-1 {{Taking false branch}}
    return 0;
  return handlers[cdb[1]]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                           // expected-note@-1 {{device request callback parameter 'cdb' is guest-controlled}}
                           // expected-note@-2 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static int scsi_device_parse_cdb(SCSIDevice *dev, SCSICommand *command,
                                 uint8_t *cdb, size_t cdb_length,
                                 void *hba_private) {
  int handlers[4] = {0};
  if (cdb_length < 2) // expected-note {{Assuming 'cdb_length' is >= 2}}
                       // expected-note@-1 {{Taking false branch}}
    return 0;
  return handlers[cdb[1]]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                           // expected-note@-1 {{device request callback parameter 'cdb' is guest-controlled}}
                           // expected-note@-2 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static int scsi_send_command(SCSIRequest *request, uint8_t *cdb) {
  int handlers[4] = {0};
  if (request->cmd.len < 2) // expected-note {{Assuming field 'len' is >= 2}}
                             // expected-note@-1 {{Taking false branch}}
    return 0;
  return handlers[cdb[1]]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                           // expected-note@-1 {{device request callback parameter 'cdb' is guest-controlled}}
                           // expected-note@-2 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static int scsi_parse_cdb_guarded(SCSIDevice *dev, SCSICommand *command,
                                  uint8_t *cdb, size_t cdb_length,
                                  void *hba_private) {
  int handlers[4] = {0};
  if (cdb_length == 0)
    return 0;
  if (cdb[0] >= 4)
    return 0;
  return handlers[cdb[0]];
}

static int scsi_parse_cdb_signature_spoof(SCSIDevice *dev,
                                          SCSICommand *command,
                                          uint32_t *cdb, size_t cdb_length,
                                          void *hba_private) {
  int handlers[4] = {0};
  return handlers[cdb[0]];
}

static const SCSIBusInfo scsi_bus_info = {
    .parse_cdb = scsi_parse_cdb,
};

static const SCSIBusInfo guarded_scsi_bus_info = {
    .parse_cdb = scsi_parse_cdb_guarded,
};

static const SCSIBusInfo spoofed_scsi_bus_info = {
    .parse_cdb = (int (*)(SCSIDevice *, SCSICommand *, uint8_t *, size_t,
                          void *))scsi_parse_cdb_signature_spoof,
};

static const SCSIReqOps scsi_request_ops = {
    .send_command = scsi_send_command,
};

static void register_scsi_device_callback(SCSIDeviceClass *sdc) {
  sdc->parse_cdb = scsi_device_parse_cdb;
}
