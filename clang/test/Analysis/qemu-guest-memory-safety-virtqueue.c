// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety -analyzer-output=text -verify %s

typedef __SIZE_TYPE__ size_t;
typedef __UINT32_TYPE__ uint32_t;

struct iovec {
  void *iov_base;
  size_t iov_len;
};

typedef struct VirtQueue VirtQueue;
typedef struct VirtQueueElement {
  unsigned out_num;
  unsigned in_num;
  struct iovec *in_sg;
  struct iovec *out_sg;
} VirtQueueElement;

void *virtqueue_pop(VirtQueue *, size_t);
size_t iov_to_buf(const struct iovec *, unsigned, size_t, void *, size_t);
void *g_memdup2(const void *, size_t);
void *g_malloc0_n(size_t, size_t);
unsigned iov_copy(struct iovec *, unsigned, const struct iovec *, unsigned,
                  size_t, size_t);

static unsigned virtqueue_request_index(VirtQueue *vq) {
  VirtQueueElement *elem = virtqueue_pop(vq, sizeof(*elem));
  unsigned index;
  int slots[4] = {0};
  if (!elem) // expected-note {{Assuming 'elem' is non-null}} expected-note {{Taking false branch}}
    return 0;
  if (iov_to_buf(elem->out_sg, elem->out_num, 0, &index, sizeof(index)) != // expected-note {{virtqueue request populated guest-controlled data here}}
      sizeof(index))
    // expected-note@-2 {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static unsigned failed_virtqueue_copy_is_not_a_source(VirtQueue *vq) {
  VirtQueueElement *elem = virtqueue_pop(vq, sizeof(*elem));
  unsigned index;
  int slots[4] = {0};
  if (!elem)
    return 0;
  if (iov_to_buf(elem->out_sg, elem->out_num, 0, &index, sizeof(index)) ==
      sizeof(index))
    return 0;
  return slots[index];
}

static unsigned unrelated_iovec_is_not_a_source(struct iovec *iov,
                                                 unsigned iov_cnt) {
  unsigned index;
  int slots[4] = {0};
  if (iov_to_buf(iov, iov_cnt, 0, &index, sizeof(index)) != sizeof(index))
    return 0;
  return slots[index];
}

static unsigned virtqueue_iovec_alias(VirtQueue *vq) {
  VirtQueueElement *elem = virtqueue_pop(vq, sizeof(*elem));
  unsigned index;
  int slots[4] = {0};
  if (!elem) // expected-note {{Assuming 'elem' is non-null}} expected-note {{Taking false branch}}
    return 0;
  struct iovec *out = elem->out_sg;
  if (iov_to_buf(out, elem->out_num, 0, &index, sizeof(index)) != // expected-note {{virtqueue request populated guest-controlled data here}}
      sizeof(index))
    // expected-note@-2 {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

typedef struct VirtioEmbeddedRequest {
  int private_data;
  VirtQueueElement elem;
} VirtioEmbeddedRequest;

static unsigned embedded_virtqueue_element(VirtQueue *vq) {
  VirtioEmbeddedRequest *req = virtqueue_pop(vq, sizeof(*req));
  unsigned index;
  int slots[4] = {0};
  if (!req) // expected-note {{Assuming 'req' is non-null}} expected-note {{Taking false branch}}
    return 0;
  if (iov_to_buf(req->elem.out_sg, req->elem.out_num, 0, &index, // expected-note {{virtqueue request populated guest-controlled data here}} expected-note {{Taking false branch}}
                 sizeof(index)) !=
      sizeof(index))
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static unsigned copied_virtqueue_iovec(VirtQueue *vq) {
  VirtQueueElement *elem = virtqueue_pop(vq, sizeof(*elem));
  unsigned index;
  int slots[4] = {0};
  if (!elem) // expected-note {{Assuming 'elem' is non-null}} expected-note {{Taking false branch}}
    return 0;
  struct iovec *copy = g_memdup2(elem->out_sg,
                                 sizeof(*copy) * elem->out_num);
  if (iov_to_buf(copy, elem->out_num, 0, &index, sizeof(index)) != // expected-note {{virtqueue request populated guest-controlled data here}}
      sizeof(index))
    // expected-note@-2 {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static unsigned sliced_virtqueue_iovec(VirtQueue *vq) {
  VirtQueueElement *elem = virtqueue_pop(vq, sizeof(*elem));
  struct iovec copy[2];
  unsigned index;
  int slots[4] = {0};
  if (!elem) // expected-note {{Assuming 'elem' is non-null}} expected-note {{Taking false branch}}
    return 0;
  unsigned count = iov_copy(copy, 2, elem->out_sg, elem->out_num, 0, -1);
  if (iov_to_buf(copy, count, 0, &index, sizeof(index)) != // expected-note {{virtqueue request populated guest-controlled data here}}
      sizeof(index))
    // expected-note@-2 {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static unsigned incoming_iovec_is_not_a_source(VirtQueue *vq) {
  VirtQueueElement *elem = virtqueue_pop(vq, sizeof(*elem));
  unsigned index;
  int slots[4] = {0};
  if (!elem)
    return 0;
  if (iov_to_buf(elem->in_sg, elem->in_num, 0, &index, sizeof(index)) !=
      sizeof(index))
    return 0;
  return slots[index];
}

typedef struct VirtioControlRequest {
  uint32_t index;
  uint32_t reserved;
} VirtioControlRequest;

static inline uint32_t le32_to_cpu(uint32_t value) {
  return __builtin_bswap32(value); // expected-note {{virtqueue request value remains guest-controlled after byte-order conversion}}
}

static unsigned virtqueue_struct_and_endian(VirtQueue *vq) {
  VirtQueueElement *elem = virtqueue_pop(vq, sizeof(*elem));
  VirtioControlRequest request;
  int slots[4] = {0};
  if (!elem) // expected-note {{Assuming 'elem' is non-null}} expected-note {{Taking false branch}}
    return 0;
  if (iov_to_buf(elem->out_sg, elem->out_num, 0, &request, // expected-note {{virtqueue request populated guest-controlled data here}} expected-note {{Taking false branch}}
                 sizeof(request)) != sizeof(request))
    return 0;
  return slots[le32_to_cpu(request.index)]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}} expected-note {{Calling 'le32_to_cpu'}} expected-note {{Returning from 'le32_to_cpu'}} expected-note {{virtqueue request value remains guest-controlled after byte-order conversion}} expected-note {{Level B: guest-controlled array index may exceed the host object element count}}
}

static unsigned decode_virtqueue_index(struct iovec *out, unsigned out_num) {
  unsigned index;
  int slots[4] = {0};
  if (iov_to_buf(out, out_num, 0, &index, sizeof(index)) != sizeof(index)) // expected-note {{virtqueue request populated guest-controlled data here}} expected-note {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}} expected-note {{Level B: guest-controlled array index may exceed the host object element count}}
}

static unsigned virtqueue_iovec_through_wrapper(VirtQueue *vq) {
  VirtQueueElement *elem = virtqueue_pop(vq, sizeof(*elem));
  if (!elem) // expected-note {{Assuming 'elem' is non-null}} expected-note {{Taking false branch}}
    return 0;
  return decode_virtqueue_index(elem->out_sg, elem->out_num); // expected-note {{Calling 'decode_virtqueue_index'}}
}

typedef struct NestedArrayConfig {
  unsigned count;
} NestedArrayConfig;

typedef struct NestedDynamicArray {
  int *slots;
  NestedArrayConfig config;
} NestedDynamicArray;

static void initialize_nested_dynamic_array(NestedDynamicArray *array) {
  array->slots = g_malloc0_n(array->config.count, sizeof(*array->slots));
}

static unsigned bounded_nested_dynamic_array(VirtQueue *vq,
                                             NestedDynamicArray *array) {
  VirtQueueElement *elem = virtqueue_pop(vq, sizeof(*elem));
  unsigned index;
  if (!elem)
    return 0;
  if (iov_to_buf(elem->out_sg, elem->out_num, 0, &index, sizeof(index)) !=
      sizeof(index))
    return 0;
  if (index >= array->config.count)
    return 0;
  return array->slots[index];
}

static unsigned unbounded_nested_dynamic_array(VirtQueue *vq,
                                               NestedDynamicArray *array) {
  VirtQueueElement *elem = virtqueue_pop(vq, sizeof(*elem));
  unsigned index;
  if (!elem) // expected-note {{Assuming 'elem' is non-null}} expected-note {{Taking false branch}}
    return 0;
  if (iov_to_buf(elem->out_sg, elem->out_num, 0, &index, // expected-note {{virtqueue request populated guest-controlled data here}} expected-note {{Taking false branch}}
                 sizeof(index)) != sizeof(index))
    return 0;
  return array->slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}} expected-note {{Level B: guest-controlled array index may exceed the host object element count}}
}
