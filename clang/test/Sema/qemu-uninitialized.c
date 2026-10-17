// RUN: %clang_cc1 -fsyntax-only -Wconditional-uninitialized \
// RUN:   -verify=maybe,first %s
// RUN: %clang_cc1 -fsyntax-only -Wconditional-uninitialized \
// RUN:   -Wconditional-uninitialized-correlated -verify=maybe,corr %s

typedef _Bool bool;
typedef unsigned long long uint64_t;

void use_int(int);
void use_uint(unsigned);
void use_long(long);
void use_ptr(const void *);
void die(void) __attribute__((noreturn));

/* QEMU's cleanup guards are single-iteration pointer loops. */
typedef struct GraphLockable GraphLockable;
GraphLockable *graph_lockable_auto_lock(GraphLockable *);
void graph_lockable_auto_unlock(GraphLockable **);

#define GRAPH_AUTO_UNLOCK __attribute__((cleanup(graph_lockable_auto_unlock)))
#define WITH_GRAPH_RDLOCK_GUARD_(var)                                      \
  for (GraphLockable *unlock_var GRAPH_AUTO_UNLOCK =                       \
           graph_lockable_auto_lock((GraphLockable *)1),                   \
       *var = unlock_var; var; var = (void *)0)
#define WITH_GRAPH_RDLOCK_GUARD()                                          \
  WITH_GRAPH_RDLOCK_GUARD_(graph_lockable_auto0)

void graph_guard_initializes(void) {
  int value; // corr-note {{variable 'value' is declared here}}
  WITH_GRAPH_RDLOCK_GUARD() {
    value = 1;
  }
  use_int(value); // corr-warning {{variable 'value' is uninitialized when used here only on paths that an earlier condition excludes}}
}

int get_status(void);

void graph_guard_in_branch(bool guarded) {
  int value; // corr-note {{variable 'value' is declared here}}
  if (guarded) {
    WITH_GRAPH_RDLOCK_GUARD() {
      value = get_status();
    }
  } else {
    value = get_status();
  }
  use_int(value); // corr-warning {{variable 'value' is uninitialized when used here only on paths that an earlier condition excludes}}
}

void graph_guard_can_break(bool stop) {
  int value; // maybe-note {{initialize the variable 'value' to silence this warning}}
  WITH_GRAPH_RDLOCK_GUARD() {
    if (stop) {
      break;
    }
    value = 1;
  }
  use_int(value); // maybe-warning {{variable 'value' may be uninitialized when used here}}
}

typedef struct QemuLockable QemuLockable;
QemuLockable *qemu_lockable_auto_lock(QemuLockable *);
void qemu_lockable_auto_unlock(QemuLockable **);

#define WITH_QEMU_LOCK_GUARD_(lock, var)                                   \
  for (QemuLockable *var                                                   \
           __attribute__((cleanup(qemu_lockable_auto_unlock))) =           \
           qemu_lockable_auto_lock((lock));                                \
       var; var = (void *)0)
#define WITH_QEMU_LOCK_GUARD(lock)                                         \
  WITH_QEMU_LOCK_GUARD_((lock), qemu_lockable_auto0)

void qemu_guard_initializes(QemuLockable *lock) {
  int value; // corr-note {{variable 'value' is declared here}}
  WITH_QEMU_LOCK_GUARD(lock) {
    value = 1;
  }
  use_int(value); // corr-warning {{variable 'value' is uninitialized when used here only on paths that an earlier condition excludes}}
}

/* Similar nullable loops must remain warnings. */
GraphLockable *maybe_lock(GraphLockable *);

void nullable_guard_does_not_initialize(void) {
  int value; // maybe-note {{initialize the variable 'value' to silence this warning}}
  for (GraphLockable *guard = maybe_lock((GraphLockable *)1); guard;
       guard = (void *)0) {
    value = 1;
  }
  use_int(value); // maybe-warning {{variable 'value' may be uninitialized when used here}}
}

/* A QEMU helper with unconditional output parameters. */
void bdrv_round_to_subclusters(void *, long, long, long *, long *);

void unconditional_outputs(void) {
  long head;
  long tail;
  bdrv_round_to_subclusters((void *)0, 0, 0, &head, &tail);
  use_long(head);
  use_long(tail);
}

int bdrv_co_block_status_above(void *, void *, long, long, long *, long *,
                               void **);

void block_status_initializes_on_error(void) {
  long count;
  (void)bdrv_co_block_status_above((void *)0, (void *)0, 0, 4096, &count,
                                   (long *)0, (void **)0);
  use_long(count);
}

/* True-on-success output contracts. */
bool v7m_stack_read(void *, unsigned *, unsigned, int);

void true_result_checked_directly(void *cpu) {
  unsigned value; // corr-note {{variable 'value' is declared here}}
  if (v7m_stack_read(cpu, &value, 0, 0)) {
    use_uint(value); // corr-warning {{variable 'value' is uninitialized when used here only on paths that an earlier condition excludes}}
  }
}

void true_result_checked_through_chain(void *cpu, bool ok) {
  unsigned value; // corr-note {{variable 'value' is declared here}}
  ok = ok && v7m_stack_read(cpu, &value, 0, 0);
  if (!ok) {
    return;
  }
  use_uint(value); // corr-warning {{variable 'value' is uninitialized when used here only on paths that an earlier condition excludes}}
}

void true_result_ignored(void *cpu) {
  unsigned value; // maybe-note {{initialize the variable 'value' to silence this warning}}
  (void)v7m_stack_read(cpu, &value, 0, 0);
  use_uint(value); // maybe-warning {{variable 'value' may be uninitialized when used here}}
}

/* Annotation-backed zero-on-success output contracts. */
#define QEMU_ANNOTATE(value) __attribute__((annotate(value)))
#define output_on_success QEMU_ANNOTATE("qemu::output_on_success")
int parse_value(const char *, int *value output_on_success);

void zero_result_checked(void) {
  int value; // corr-note {{variable 'value' is declared here}}
  if (parse_value("1", &value)) {
    return;
  }
  use_int(value); // corr-warning {{variable 'value' is uninitialized when used here only on paths that an earlier condition excludes}}
}

void zero_result_ignored(void) {
  int value; // maybe-note {{initialize the variable 'value' to silence this warning}}
  (void)parse_value("1", &value);
  use_int(value); // maybe-warning {{variable 'value' may be uninitialized when used here}}
}

/* QEMU's numeric parsers store a defined value on both success and failure. */
int qemu_strtoi(const char *, const char **, int, int *);

void numeric_parser_always_initializes(void) {
  int value;
  (void)qemu_strtoi("not a number", (const char **)0, 10, &value);
  use_int(value);
}

/* Nonnegative-on-success output contracts used by NBD. */
int nbd_co_receive_return_code(void *, void *, int *);

int nbd_result_checked(void *client, void *request) {
  int request_ret; // corr-note {{variable 'request_ret' is declared here}}
  int ret = nbd_co_receive_return_code(client, request, &request_ret);
  if (ret < 0) {
    return ret;
  }
  return request_ret; // corr-warning {{variable 'request_ret' is uninitialized when used here only on paths that an earlier condition excludes}}
}

int nbd_zero_result_selects_output(void *client, void *request) {
  int request_ret; // corr-note {{variable 'request_ret' is declared here}}
  int ret = nbd_co_receive_return_code(client, request, &request_ret);
  return ret ? ret : request_ret; // corr-warning {{variable 'request_ret' is uninitialized when used here only on paths that an earlier condition excludes}}
}

int nbd_result_ignored(void *client, void *request) {
  int request_ret; // maybe-note {{initialize the variable 'request_ret' to silence this warning}}
  (void)nbd_co_receive_return_code(client, request, &request_ret);
  return request_ret; // maybe-warning {{variable 'request_ret' may be uninitialized when used here}}
}

/* Snapshot arrays are initialized only when the returned count is nonnegative. */
int bdrv_snapshot_list(void *, const void **);

void snapshot_list_result_checked(void *bs) {
  const void *snapshots; // corr-note {{variable 'snapshots' is declared here}}
  int count = bdrv_snapshot_list(bs, &snapshots);
  if (count < 0) {
    return;
  }
  use_ptr(snapshots); // corr-warning {{variable 'snapshots' is uninitialized when used here only on paths that an earlier condition excludes}}
}

void snapshot_list_checked_after_many_conditions(
    void *bs, int a0, int a1, int a2, int a3, int a4, int a5, int a6, int a7,
    int a8) {
  const void *snapshots; // corr-note {{variable 'snapshots' is declared here}}
  int count = bdrv_snapshot_list(bs, &snapshots);
  if (count < 0) {
    return;
  }
  if (a0 && a1 && a2 && a3 && a4 && a5 && a6 && a7 && a8) {
    use_ptr(snapshots); // corr-warning {{variable 'snapshots' is uninitialized when used here only on paths that an earlier condition excludes}}
  }
}

void snapshot_list_error_falls_through(void *bs) {
  const void *snapshots; // first-note {{initialize the variable 'snapshots' to silence this warning}}
                         // corr-note@-1 {{variable 'snapshots' is declared here}}
  int count = bdrv_snapshot_list(bs, &snapshots);
  for (int i = 0; i < count; ++i) {
    use_ptr(snapshots); // corr-warning {{variable 'snapshots' is uninitialized when used here only on paths that an earlier condition excludes}}
  }
  use_ptr(snapshots); // first-warning {{variable 'snapshots' may be uninitialized when used here}}
}

/* QEMU's strstart() initializes its suffix output only on a match. */
int strstart(const char *, const char *, const char **);

void strstart_direct(const char *input) {
  const char *suffix; // corr-note {{variable 'suffix' is declared here}}
  if (strstart(input, "prefix", &suffix)) {
    use_ptr(suffix); // corr-warning {{variable 'suffix' is uninitialized when used here only on paths that an earlier condition excludes}}
  }
}

void strstart_counted_loop(const char *input) {
  const char *suffix; // corr-note {{variable 'suffix' is declared here}}
  int i;
  for (i = 0; i < 3; ++i) {
    if (strstart(input, "prefix", &suffix)) {
      break;
    }
  }
  if (i == 3) {
    die();
  }
  use_ptr(suffix); // corr-warning {{variable 'suffix' is uninitialized when used here only on paths that an earlier condition excludes}}
}

/* The qcow2 pattern is a real warning: the loop may execute zero times. */
void qcow2_empty_loop(uint64_t bytes) {
  unsigned cur_bytes; // maybe-note {{initialize the variable 'cur_bytes' to silence this warning}}
  while (bytes) {
    cur_bytes = bytes > 4096 ? 4096 : (unsigned)bytes;
    bytes -= cur_bytes;
  }
  use_uint(cur_bytes); // maybe-warning {{variable 'cur_bytes' may be uninitialized when used here}}
}
