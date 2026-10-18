// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.ResourceLifetime \
// RUN:   -analyzer-config ipa=none -verify %s

typedef __SIZE_TYPE__ size_t;
typedef __PTRDIFF_TYPE__ ssize_t;

typedef struct NetQueue NetQueue;
typedef struct NetClientState NetClientState;
struct iovec {
  void *iov_base;
  size_t iov_len;
};
typedef void NetPacketSent(NetClientState *sender, ssize_t ret);

void g_free(void *ptr);

ssize_t qemu_sendv_packet_async(NetClientState *sender,
                                const struct iovec *iov, int iovcnt,
                                NetPacketSent *sent_cb);
ssize_t qemu_net_queue_send(NetQueue *queue, NetClientState *sender,
                            unsigned flags, const unsigned char *data,
                            size_t size, NetPacketSent *sent_cb);

/* Deliberate same-name lookalikes with non-QEMU signatures. */
ssize_t qemu_send_packet_async(NetClientState *sender,
                               const unsigned char *buf, int size,
                               void *not_a_callback);
void qemu_purge_queued_packets(NetClientState *sender, int extra);
void qemu_net_queue_purge(NetQueue *queue, NetClientState *sender, int extra);

static void packet_sent(NetClientState *sender, ssize_t ret) {}

void wrong_send_signature_is_not_modeled(NetClientState *sender,
                                         const unsigned char *buf) {
  if (qemu_send_packet_async(sender, buf, 8, (void *)1) == 0)
    g_free(sender);
}

void wrong_peer_purge_signature_does_not_discharge(
    NetClientState *sender, const struct iovec *iov) {
  // expected-note@+1 {{Packet queued here}}
  if (qemu_sendv_packet_async(sender, iov, 1, packet_sent) == 0) {
    qemu_purge_queued_packets(sender, 0);
    g_free(sender); // expected-warning {{Object is released while a queued network packet can still use it}}
  }
}

void wrong_direct_purge_signature_does_not_discharge(
    NetQueue *queue, NetClientState *sender, const unsigned char *buf) {
  // expected-note@+1 {{Packet queued here}}
  if (qemu_net_queue_send(queue, sender, 0, buf, 8, packet_sent) == 0) {
    qemu_net_queue_purge(queue, sender, 0);
    g_free(sender); // expected-warning {{Object is released while a queued network packet can still use it}}
  }
}
