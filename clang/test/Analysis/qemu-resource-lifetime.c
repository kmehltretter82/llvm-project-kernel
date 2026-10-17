// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.ResourceLifetime \
// RUN:   -analyzer-config ipa=none -verify %s

typedef __SIZE_TYPE__ size_t;

typedef struct Foo Foo;
typedef struct Object Object;
typedef struct QObject QObject;
typedef struct QDict QDict;

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

#define QOBJECT(obj) ((QObject *)(obj))
#define FREE_BUFFER(ptr) g_free(ptr)

typedef struct ListNode {
  struct ListNode *next;
} ListNode;

#define QLIST_FOREACH_SAFE(item, head, next_item)                            \
  for ((item) = *(head);                                                     \
       (item) && (((next_item) = (item)->next), 1); (item) = (next_item))

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
