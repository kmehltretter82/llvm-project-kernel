// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.ResourceLifetime \
// RUN:   -analyzer-config ipa=none -verify %s

typedef __SIZE_TYPE__ size_t;

typedef struct Foo Foo;
typedef struct Object Object;
typedef struct QObject QObject;
typedef struct QDict QDict;
typedef struct QEMUBH QEMUBH;
typedef struct QEMUTimer QEMUTimer;
typedef struct BlockAIOCB BlockAIOCB;
typedef struct Coroutine Coroutine;
typedef struct EventNotifier {
  int fd;
} EventNotifier;
typedef struct QemuEvent {
  int value;
} QemuEvent;
typedef struct QemuThread {
  int value;
} QemuThread;
typedef void QEMUBHFunc(void *opaque);
typedef void QEMUTimerCB(void *opaque);
typedef void BlockCompletionFunc(void *opaque, int ret);
typedef void CoroutineEntry(void *opaque);
typedef void EventNotifierHandler(EventNotifier *notifier);

void g_free(void *ptr);
void qapi_free_Foo(Foo *foo);
void use_pointer(const void *ptr);
void use_foo(const Foo *foo);
char *new_buffer(void);
Foo *new_foo(void);

Object *object_new(const char *type);
Object *object_ref(void *obj);
void object_unref(void *obj);
void use_object(const Object *obj);

QDict *qdict_new(void);
void qobject_ref_impl(QObject *obj);
void qobject_unref_impl(QObject *obj);

int close(int fd);
long read(int fd, void *buf, size_t count);
int open_again(void);

QEMUBH *qemu_bh_new_full(QEMUBHFunc *cb, void *opaque, const char *name,
                         void *guard);
void qemu_bh_schedule(QEMUBH *bh);
void qemu_bh_cancel(QEMUBH *bh);
void qemu_bh_delete(QEMUBH *bh);
void aio_bh_schedule_oneshot_full(void *ctx, QEMUBHFunc *cb, void *opaque,
                                  const char *name);
int aio_poll(void *ctx, int blocking);
void main_loop_wait(int blocking);
int g_main_context_iteration(void *ctx, int blocking);
void qemu_event_wait(QemuEvent *event);
void qemu_thread_join(QemuThread *thread);

QEMUTimer *timer_new_ns(int type, QEMUTimerCB *cb, void *opaque);
void timer_mod_ns(QEMUTimer *timer, long expires);
void timer_del(QEMUTimer *timer);
void timer_free(QEMUTimer *timer);
int timer_pending(QEMUTimer *timer);

BlockAIOCB *blk_aio_preadv(void *blk, long offset, void *qiov,
                           unsigned flags, BlockCompletionFunc *cb,
                           void *opaque);
void blk_aio_cancel(BlockAIOCB *acb);

Coroutine *qemu_coroutine_create(CoroutineEntry *entry, void *opaque);
void qemu_coroutine_enter(Coroutine *co);
void aio_co_wake(Coroutine *co);
void aio_co_schedule(void *ctx, Coroutine *co);
void qemu_coroutine_yield(void);
void qemu_co_sleep_ns_wakeable(void *state, int type, unsigned long timeout);

void defer_call_begin(void);
void defer_call(void (*fn)(void *), void *opaque);
void defer_call_end(void);
void aio_set_event_notifier(void *ctx, EventNotifier *notifier,
                            EventNotifierHandler *io_read, void *io_poll,
                            EventNotifierHandler *io_poll_ready);
void event_notifier_set_handler(EventNotifier *notifier,
                                EventNotifierHandler *handler);
void aio_set_fd_handler(void *ctx, int fd, QEMUBHFunc *io_read,
                        QEMUBHFunc *io_write, void *io_poll,
                        QEMUBHFunc *io_poll_ready, void *opaque);
void qemu_set_fd_handler(int fd, QEMUBHFunc *io_read,
                         QEMUBHFunc *io_write, void *opaque);

#define AIO_WAIT_WHILE(ctx, cond)                                          \
  ({                                                                       \
    if (cond)                                                              \
      aio_poll(ctx, 1);                                                    \
  })

#define QOBJECT(obj) ((QObject *)(obj))
#define FREE_BUFFER(ptr) g_free(ptr)

typedef struct ListNode {
  struct ListNode *next;
} ListNode;

typedef struct QueueNode QueueNode;
typedef struct QueueHead {
  QueueNode *lh_first;
} QueueHead;

struct QueueNode {
  struct {
    QueueNode *le_next;
    QueueNode **le_prev;
  } next;
  char *payload;
};

#define QLIST_FOREACH_SAFE(item, head, next_item)                            \
  for ((item) = *(head);                                                     \
       (item) && (((next_item) = (item)->next), 1); (item) = (next_item))
#define QLIST_FIRST(head) ((head)->lh_first)
#define QLIST_EMPTY(head) (QLIST_FIRST(head) == 0)
#define QLIST_REMOVE(item, field)                                            \
  (*(item)->field.le_prev = (item)->field.le_next)

static inline void g_autoptr_cleanup_generic_gfree(void *slot) {
  void **ptr = slot;
  g_free(*ptr);
}

static inline void glib_autoptr_clear_Foo(Foo *foo) {
  if (foo)
    qapi_free_Foo(foo);
}

static inline void glib_autoptr_cleanup_Foo(Foo **foo) {
  glib_autoptr_clear_Foo(*foo);
}

static inline void glib_autoptr_clear_Object(Object *obj) {
  if (obj)
    object_unref(obj);
}

static inline void glib_autoptr_cleanup_Object(Object **obj) {
  glib_autoptr_clear_Object(*obj);
}

static inline void qdict_unref(QDict *dict) {
  qobject_unref_impl(QOBJECT(dict));
}

static inline void glib_autoptr_clear_QDict(QDict *dict) {
  if (dict)
    qdict_unref(dict);
}

static inline void glib_autoptr_cleanup_QDict(QDict **dict) {
  glib_autoptr_clear_QDict(*dict);
}

void double_g_free(char *ptr) {
  if (!ptr)
    return;
  g_free(ptr); // expected-note {{Pointer first released here}}
  g_free(ptr); // expected-warning {{Pointer released by g_free is released again}}
}

void use_after_g_free(char *ptr) {
  if (!ptr)
    return;
  g_free(ptr); // expected-note {{Pointer released here}}
  use_pointer(ptr); // expected-warning {{Pointer is passed to 'use_pointer' after it was released by g_free}}
}

int dereference_after_g_free(char *ptr) {
  if (!ptr)
    return 0;
  g_free(ptr); // expected-note {{Pointer released here}}
  return ptr[0]; // expected-warning {{Pointer is dereferenced after it was released by g_free}}
}

void macro_double_free(char *ptr) {
  if (!ptr)
    return;
  FREE_BUFFER(ptr); // expected-note {{Pointer first released here}}
  FREE_BUFFER(ptr); // expected-warning {{Pointer released by g_free is released again}}
}

void cleanup_double_free(char *ptr) {
  if (!ptr)
    return;
  g_free(ptr); // expected-note {{Pointer first released here}}
  g_autoptr_cleanup_generic_gfree(&ptr); // expected-warning {{Pointer released by g_free is released again}}
}

void mutually_exclusive_free_is_safe(char *ptr, int first) {
  if (!ptr)
    return;
  if (first)
    g_free(ptr);
  else
    use_pointer(ptr);
}

void reset_to_null_is_safe(char *ptr) {
  g_free(ptr);
  ptr = 0;
  g_free(ptr);
}

void intrusive_queue_loop_is_safe(ListNode **head) {
  ListNode *item;
  ListNode *next_item;
  QLIST_FOREACH_SAFE(item, head, next_item) {
    g_free(item);
  }
}

void remove_queue_head_loop_is_safe(QueueHead *head) {
  while (!QLIST_EMPTY(head)) {
    QueueNode *item = QLIST_FIRST(head);
    QLIST_REMOVE(item, next);
    g_free(item->payload);
    g_free(item);
  }
}

void free_before_queue_remove_is_unsafe(QueueNode *item) {
  if (!item->next.le_prev)
    return;
  g_free(item); // expected-note 2 {{Pointer released here}}
  // expected-warning@+1 2 {{Pointer is dereferenced after it was released by g_free}}
  QLIST_REMOVE(item, next);
}

void queue_loop_without_rebind_is_unsafe(QueueHead *head) {
  QueueNode *item = QLIST_FIRST(head);
  if (!item->next.le_prev)
    return;
  for (int i = 0; i < 2; i++) {
    // expected-warning@+1 2 {{Pointer is dereferenced after it was released by g_free}}
    QLIST_REMOVE(item, next);
    if (i == 0)
      g_free(item); // expected-note 2 {{Pointer released here}}
  }
}

void alias_survives_source_rebind(char *ptr) {
  if (!ptr)
    return;
  char *alias = ptr;
  g_free(ptr); // expected-note {{Pointer released here}}
  ptr = new_buffer();
  use_pointer(alias); // expected-warning {{Pointer is passed to 'use_pointer' after it was released by g_free}}
}

void double_qapi_free(Foo *foo) {
  if (!foo)
    return;
  qapi_free_Foo(foo); // expected-note {{Pointer first released here}}
  qapi_free_Foo(foo); // expected-warning {{Pointer released by QAPI free is released again}}
}

void use_after_qapi_free(Foo *foo) {
  if (!foo)
    return;
  qapi_free_Foo(foo); // expected-note {{Pointer released here}}
  use_foo(foo); // expected-warning {{Pointer is passed to 'use_foo' after it was released by QAPI free}}
}

void qapi_cleanup_double_free(Foo *foo) {
  if (!foo)
    return;
  qapi_free_Foo(foo); // expected-note {{Pointer first released here}}
  glib_autoptr_cleanup_Foo(&foo); // expected-warning {{Pointer released by QAPI free is released again}}
}

void double_qom_unref(void) {
  Object *obj = object_new("test");
  if (!obj)
    return;
  object_unref(obj); // expected-note {{Owned reference first released here}}
  object_unref(obj); // expected-warning {{Owned QOM reference is released more than once}}
}

void balanced_qom_refs(void) {
  Object *obj = object_new("test");
  if (!obj)
    return;
  object_ref(obj);
  object_unref(obj);
  object_unref(obj);
}

void qom_cleanup_double_unref(void) {
  Object *obj = object_new("test");
  if (!obj)
    return;
  object_unref(obj); // expected-note {{Owned reference first released here}}
  glib_autoptr_cleanup_Object(&obj); // expected-warning {{Owned QOM reference is released more than once}}
}

void borrowed_qom_ownership_is_unknown(Object *obj) {
  object_unref(obj);
  object_unref(obj);
}

void double_qobject_unref(void) {
  QDict *dict = qdict_new();
  if (!dict)
    return;
  qobject_unref_impl(QOBJECT(dict)); // expected-note {{Owned reference first released here}}
  qobject_unref_impl(QOBJECT(dict)); // expected-warning {{Owned QObject reference is released more than once}}
}

void balanced_qobject_refs(void) {
  QDict *dict = qdict_new();
  if (!dict)
    return;
  qobject_ref_impl(QOBJECT(dict));
  qobject_unref_impl(QOBJECT(dict));
  qobject_unref_impl(QOBJECT(dict));
}

void qobject_cleanup_double_unref(void) {
  QDict *dict = qdict_new();
  if (!dict)
    return;
  qobject_unref_impl(QOBJECT(dict)); // expected-note {{Owned reference first released here}}
  glib_autoptr_cleanup_QDict(&dict); // expected-warning {{Owned QObject reference is released more than once}}
}

__attribute__((annotate("qemu::returns_owned_qom"))) Object *new_qom_wrapper(void);
__attribute__((annotate("qemu::unrefs_qom"))) void unref_qom_wrapper(Object *);

void annotated_qom_contract(void) {
  Object *obj = new_qom_wrapper();
  if (!obj)
    return;
  unref_qom_wrapper(obj); // expected-note {{Owned reference first released here}}
  unref_qom_wrapper(obj); // expected-warning {{Owned QOM reference is released more than once}}
}

void indirect_free_is_conservative(char *ptr, void (*release)(void *)) {
  if (!ptr)
    return;
  release(ptr);
  use_pointer(ptr);
}

__attribute__((suppress)) void explicitly_suppressed_pointer_warning(char *ptr) {
  if (!ptr)
    return;
  g_free(ptr);
  g_free(ptr);
}

void double_close(int fd) {
  if (fd < 0)
    return;
  close(fd); // expected-note {{File descriptor first closed here}}
  close(fd); // expected-warning {{File descriptor is closed more than once}}
}

void read_after_close(int fd, char *buf) {
  if (fd < 0)
    return;
  close(fd); // expected-note {{File descriptor closed here}}
  read(fd, buf, 1); // expected-warning {{Closed file descriptor is passed to 'read'}}
}

void reassigned_fd_is_safe(int fd) {
  if (fd < 0)
    return;
  close(fd);
  fd = open_again();
  if (fd >= 0)
    close(fd);
}

void negative_fd_is_safe(void) {
  close(-1);
  close(-1);
}

void mutually_exclusive_close_is_safe(int fd, int first) {
  if (fd < 0)
    return;
  if (first)
    close(fd);
  else
    read(fd, 0, 0);
}

__attribute__((annotate("qemu::closes_fd"))) void close_wrapper(int fd);

void annotated_double_close(int fd) {
  if (fd < 0)
    return;
  close_wrapper(fd); // expected-note {{File descriptor first closed here}}
  close_wrapper(fd); // expected-warning {{File descriptor is closed more than once}}
}

static void async_callback(void *opaque) {}
static void block_callback(void *opaque, int ret) {}
static void notifier_callback(EventNotifier *notifier) {}

typedef struct NotifierOwner {
  EventNotifier notifier;
  int value;
} NotifierOwner;

void release_with_scheduled_bh(char *ptr) {
  if (!ptr)
    return;
  QEMUBH *bh = qemu_bh_new_full(async_callback, ptr, "test", 0);
  qemu_bh_schedule(bh); // expected-note {{Callback made pending here}}
  g_free(ptr); // expected-warning {{Object is released while a pending bottom-half callback can still use it}}
}

void cancel_bh_before_release_is_safe(char *ptr) {
  QEMUBH *bh = qemu_bh_new_full(async_callback, ptr, "test", 0);
  qemu_bh_schedule(bh);
  qemu_bh_cancel(bh);
  g_free(ptr);
}

void delete_bh_before_release_is_safe(char *ptr) {
  QEMUBH *bh = qemu_bh_new_full(async_callback, ptr, "test", 0);
  qemu_bh_schedule(bh);
  qemu_bh_delete(bh);
  g_free(ptr);
}

void dormant_bh_does_not_retain_live_use(char *ptr) {
  qemu_bh_new_full(async_callback, ptr, "test", 0);
  g_free(ptr);
}

void release_with_oneshot_bh(char *ptr) {
  aio_bh_schedule_oneshot_full(0, async_callback, ptr, "test"); // expected-note {{Callback made pending here}}
  g_free(ptr); // expected-warning {{Object is released while a pending bottom-half callback can still use it}}
}

void oneshot_bh_poll_before_release_is_safe(char *ptr) {
  aio_bh_schedule_oneshot_full(0, async_callback, ptr, "test");
  aio_poll(0, 0);
  g_free(ptr);
}

void oneshot_bh_single_glib_iteration_is_not_a_barrier(char *ptr) {
  aio_bh_schedule_oneshot_full(0, async_callback, ptr, "test"); // expected-note {{Callback made pending here}}
  g_main_context_iteration(0, 1);
  g_free(ptr); // expected-warning {{Object is released while a pending bottom-half callback can still use it}}
}

typedef struct EventOwner {
  QemuEvent event;
  int result;
} EventOwner;

void stack_oneshot_event_wait_is_safe(void) {
  EventOwner owner;
  aio_bh_schedule_oneshot_full(0, async_callback, &owner, "test");
  qemu_event_wait(&owner.event);
}

void unrelated_event_wait_keeps_pending_stack(QemuEvent *other) {
  EventOwner owner;
  aio_bh_schedule_oneshot_full(0, async_callback, &owner, "test");
  qemu_event_wait(other);
  return; // expected-warning {{Address of stack object is retained by a pending bottom-half callback}}
}

typedef struct ThreadOwner {
  QemuThread thread;
  int result;
} ThreadOwner;

void oneshot_thread_join_before_release_is_safe(ThreadOwner *owner) {
  aio_bh_schedule_oneshot_full(0, async_callback, owner, "test");
  qemu_thread_join(&owner->thread);
  g_free(owner);
}

void unrelated_thread_join_keeps_pending_release(ThreadOwner *owner,
                                                 QemuThread *other) {
  aio_bh_schedule_oneshot_full(0, async_callback, owner, "test"); // expected-note {{Callback made pending here}}
  qemu_thread_join(other);
  g_free(owner); // expected-warning {{Object is released while a pending bottom-half callback can still use it}}
}

void stack_oneshot_escape(void) {
  char buffer[8];
  aio_bh_schedule_oneshot_full(0, async_callback, buffer, "test");
  return; // expected-warning {{Address of stack object is retained by a pending bottom-half callback}}
}

void stack_oneshot_poll_is_safe(void) {
  char buffer[8];
  aio_bh_schedule_oneshot_full(0, async_callback, buffer, "test");
  aio_poll(0, 0);
}

void stack_oneshot_aio_wait_is_safe(void) {
  struct {
    int done;
    char buffer[8];
  } data;
  aio_bh_schedule_oneshot_full(0, async_callback, &data, "test");
  AIO_WAIT_WHILE(0, !data.done);
}

void unrelated_aio_wait_does_not_complete_pending_stack(int wait) {
  char buffer[8];
  aio_bh_schedule_oneshot_full(0, async_callback, buffer, "test");
  AIO_WAIT_WHILE(0, wait);
  return; // expected-warning {{Address of stack object is retained by a pending bottom-half callback}}
}

void stack_oneshot_coroutine_yield_is_safe(void) {
  char buffer[8];
  aio_bh_schedule_oneshot_full(0, async_callback, buffer, "test");
  qemu_coroutine_yield();
}

void release_with_armed_timer(char *ptr) {
  QEMUTimer *timer = timer_new_ns(0, async_callback, ptr);
  timer_mod_ns(timer, 1); // expected-note {{Callback made pending here}}
  g_free(ptr); // expected-warning {{Object is released while a pending timer callback can still use it}}
}

void timer_delete_before_release_is_safe(char *ptr) {
  QEMUTimer *timer = timer_new_ns(0, async_callback, ptr);
  timer_mod_ns(timer, 1);
  timer_del(timer);
  g_free(ptr);
}

void timer_free_before_release_is_safe(char *ptr) {
  QEMUTimer *timer = timer_new_ns(0, async_callback, ptr);
  timer_mod_ns(timer, 1);
  timer_free(timer);
  g_free(ptr);
}

void use_timer_after_free(void) {
  QEMUTimer *timer = timer_new_ns(0, async_callback, 0);
  timer_free(timer); // expected-note {{Pointer released here}}
  timer_pending(timer); // expected-warning {{Pointer is passed to 'timer_pending' after it was released by timer_free}}
}

typedef struct TimerOwner {
  QEMUTimer *timer;
} TimerOwner;

void bdrv_test_detach_aio_context(TimerOwner *owner) {
  timer_free(owner->timer); // expected-warning {{A persistent object field still points to a timer freed by timer_free}}
}

void bdrv_fixed_detach_aio_context(TimerOwner *owner) {
  timer_free(owner->timer);
  owner->timer = 0;
}

void release_with_block_aio(char *ptr) {
  blk_aio_preadv(0, 0, 0, 0, block_callback, ptr); // expected-note {{Callback made pending here}}
  g_free(ptr); // expected-warning {{Object is released while a pending block AIO callback can still use it}}
}

void block_aio_completion_loop_is_safe(void) {
  int async_ret = 1;
  blk_aio_preadv(0, 0, 0, 0, block_callback, &async_ret);
  while (async_ret == 1) {
    main_loop_wait(0);
  }
}

void unrelated_completion_loop_keeps_block_aio(int wait) {
  int async_ret = 1;
  blk_aio_preadv(0, 0, 0, 0, block_callback, &async_ret);
  while (wait) {
    main_loop_wait(0);
  }
  return; // expected-warning {{Address of stack object is retained by a pending block AIO callback}}
}

void impure_completion_loop_is_not_a_barrier(void) {
  int async_ret = 1;
  blk_aio_preadv(0, 0, 0, 0, block_callback, &async_ret);
  while (async_ret == 1) {
    main_loop_wait(0);
    break;
  }
  return; // expected-warning {{Address of stack object is retained by a pending block AIO callback}}
}

void cancel_block_aio_before_release_is_safe(char *ptr) {
  BlockAIOCB *acb = blk_aio_preadv(0, 0, 0, 0, block_callback, ptr);
  blk_aio_cancel(acb);
  g_free(ptr);
}

void stack_block_aio_escape(void) {
  int result;
  blk_aio_preadv(0, 0, 0, 0, block_callback, &result);
  return; // expected-warning {{Address of stack object is retained by a pending block AIO callback}}
}

void release_with_scheduled_coroutine(char *ptr) {
  Coroutine *co = qemu_coroutine_create(async_callback, ptr);
  aio_co_schedule(0, co); // expected-note {{Callback made pending here}}
  g_free(ptr); // expected-warning {{Object is released while a pending coroutine callback can still use it}}
}

void direct_coroutine_completion_before_release_is_safe(char *ptr) {
  Coroutine *co = qemu_coroutine_create(async_callback, ptr);
  qemu_coroutine_enter(co);
  g_free(ptr);
}

void coroutine_sleep_transfers_completion_ownership(char *ptr) {
  Coroutine *co = qemu_coroutine_create(async_callback, ptr);
  aio_co_schedule(0, co);
  qemu_co_sleep_ns_wakeable(0, 0, 1);
  g_free(ptr);
}

void release_inside_deferred_section(char *ptr) {
  defer_call_begin();
  defer_call(async_callback, ptr); // expected-note {{Callback made pending here}}
  g_free(ptr); // expected-warning {{Object is released while a pending deferred callback can still use it}}
  defer_call_end();
}

void end_deferred_section_before_release_is_safe(char *ptr) {
  defer_call_begin();
  defer_call(async_callback, ptr);
  defer_call_end();
  g_free(ptr);
}

void immediate_defer_call_before_release_is_safe(char *ptr) {
  defer_call(async_callback, ptr);
  g_free(ptr);
}

void release_with_registered_aio_notifier(NotifierOwner *owner) {
  // expected-note@+1 {{Callback registered here}}
  aio_set_event_notifier(0, &owner->notifier, notifier_callback, 0, 0);
  g_free(owner); // expected-warning {{Object is released while a registered AIO event-notifier callback can still use it}}
}

void unregister_aio_notifier_before_release_is_safe(NotifierOwner *owner) {
  aio_set_event_notifier(0, &owner->notifier, notifier_callback, 0, 0);
  aio_set_event_notifier(0, &owner->notifier, 0, 0, 0);
  g_free(owner);
}

void release_with_registered_main_loop_notifier(NotifierOwner *owner) {
  // expected-note@+1 {{Callback registered here}}
  event_notifier_set_handler(&owner->notifier, notifier_callback);
  g_free(owner); // expected-warning {{Object is released while a registered AIO event-notifier callback can still use it}}
}

void unregister_main_loop_notifier_before_release_is_safe(
    NotifierOwner *owner) {
  event_notifier_set_handler(&owner->notifier, notifier_callback);
  event_notifier_set_handler(&owner->notifier, 0);
  g_free(owner);
}

void stack_registered_notifier_escape(void) {
  EventNotifier notifier;
  event_notifier_set_handler(&notifier, notifier_callback);
  return; // expected-warning {{Address of stack object is retained by a registered AIO event-notifier callback}}
}

void stack_unregistered_notifier_is_safe(void) {
  EventNotifier notifier;
  event_notifier_set_handler(&notifier, notifier_callback);
  event_notifier_set_handler(&notifier, 0);
}

void release_with_registered_fd_handler(int fd, char *ptr) {
  // expected-note@+1 {{Callback registered here}}
  qemu_set_fd_handler(fd, async_callback, 0, ptr);
  g_free(ptr); // expected-warning {{Object is released while a registered AIO file-descriptor callback can still use it}}
}

void unregister_fd_handler_before_release_is_safe(int fd, char *ptr) {
  qemu_set_fd_handler(fd, async_callback, 0, ptr);
  qemu_set_fd_handler(fd, 0, 0, 0);
  g_free(ptr);
}

void replace_fd_handler_before_old_release_is_safe(int fd, char *old_ptr,
                                                   char *new_ptr) {
  qemu_set_fd_handler(fd, async_callback, 0, old_ptr);
  qemu_set_fd_handler(fd, async_callback, 0, new_ptr);
  g_free(old_ptr);
  qemu_set_fd_handler(fd, 0, 0, 0);
}

void unrelated_fd_unregister_keeps_registration(int fd, int other_fd,
                                                 char *ptr) {
  if (fd == other_fd)
    return;
  // expected-note@+1 {{Callback registered here}}
  qemu_set_fd_handler(fd, async_callback, 0, ptr);
  qemu_set_fd_handler(other_fd, 0, 0, 0);
  g_free(ptr); // expected-warning {{Object is released while a registered AIO file-descriptor callback can still use it}}
}

void release_with_registered_aio_fd_handler(int fd, char *ptr) {
  // expected-note@+1 {{Callback registered here}}
  aio_set_fd_handler(0, fd, async_callback, 0, 0, 0, ptr);
  g_free(ptr); // expected-warning {{Object is released while a registered AIO file-descriptor callback can still use it}}
}

void unregister_aio_fd_handler_before_release_is_safe(int fd, char *ptr) {
  aio_set_fd_handler(0, fd, async_callback, 0, 0, 0, ptr);
  aio_set_fd_handler(0, fd, 0, 0, 0, 0, 0);
  g_free(ptr);
}

void stack_registered_fd_handler_escape(int fd) {
  char buffer[8];
  qemu_set_fd_handler(fd, async_callback, 0, buffer);
  return; // expected-warning {{Address of stack object is retained by a registered AIO file-descriptor callback}}
}

typedef struct CoroutineResumeData {
  Coroutine *co;
  int fd;
} CoroutineResumeData;

static void self_unregistering_coroutine_resume(void *opaque) {
  CoroutineResumeData *data = opaque;
  qemu_set_fd_handler(data->fd, 0, 0, 0);
  qemu_coroutine_enter(data->co);
}

void stack_coroutine_resume_handler_is_safe(int fd, Coroutine *co) {
  CoroutineResumeData data = {co, fd};
  qemu_set_fd_handler(fd, self_unregistering_coroutine_resume, 0, &data);
  qemu_coroutine_yield();
}

void unref_with_scheduled_bh(void) {
  Object *obj = object_new("test");
  QEMUBH *bh = qemu_bh_new_full(async_callback, obj, "test", 0);
  qemu_bh_schedule(bh); // expected-note {{Callback made pending here}}
  object_unref(obj); // expected-warning {{Object is released while a pending bottom-half callback can still use it}}
}
