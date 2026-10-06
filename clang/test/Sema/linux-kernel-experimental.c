// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-experimental \
// RUN:   -flinux-kernel-experimental=all -verify %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-experimental \
// RUN:   -verify=off %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding \
// RUN:   -flinux-kernel-experimental=all -verify=off %s

// off-no-diagnostics

// The checks that -flinux-kernel-experimental= turns on by name.  They have
// no warning group of their own yet: all of them report under
// -Wlinux-kernel-experimental, which alone turns nothing on.

typedef _Bool bool;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef unsigned long size_t;
#define NULL ((void *)0)
#define EINVAL 22
#define ENOENT 2
#define ENOMEM 12
#define ENODEV 19
#define EIO 5
#define true 1
#define false 0
#define unlikely(x) __builtin_expect(!!(x), 0)
#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#define container_of(ptr, type, member) ({ \
  void *__mptr = (void *)(ptr); \
  ((type *)(__mptr - offsetof(type, member))); })

bool IS_ERR(const void *);
bool IS_ERR_OR_NULL(const void *);
long PTR_ERR(const void *);
void *ERR_PTR(long);
int _printk(const char *fmt, ...);
void *memcpy(void *, const void *, size_t);
void kfree(const void *);

struct dev {
  int cached;
  u32 cache;
  u8 buf[8];
  struct clk *clk;
  void *regs;
};

int xfer(struct dev *d, u8 *buf);
int use(int);
void consume(u32);

// ---------------------------------------------------------------------------
// uninit-output

static int read_reg(struct dev *d, u32 *val) {
  int ret = xfer(d, d->buf);

  if (ret < 0)
    return ret; // expected-note 5 {{'read_reg' returns here without having written through 'val'}}
  *val = d->buf[0];
  return 0;
}

int out_ignored(struct dev *d) {
  u32 val;

  read_reg(d, &val); // expected-note {{the address of 'val' is passed to 'read_reg' here}}
  return val & 1; // expected-warning {{'val' is read here, but 'read_reg' does not write to it when it fails, and the result of the call is not tested (experimental check 'uninit-output')}}
}

int out_checked(struct dev *d) {
  u32 val;
  int ret;

  ret = read_reg(d, &val);
  if (ret)
    return ret;
  return val & 1;
}

int out_checked_negative(struct dev *d) {
  u32 val;
  int ret = read_reg(d, &val);

  if (ret < 0)
    return ret;
  return val & 1;
}

int out_condition(struct dev *d) {
  u32 val;

  if (read_reg(d, &val))
    return -EIO;
  return val & 1;
}

int out_default(struct dev *d) {
  u32 val;

  if (read_reg(d, &val) < 0)
    val = 0;
  return val & 1;
}

int out_printed_on_failure(struct dev *d) {
  u32 val;
  int ret = read_reg(d, &val); // expected-note {{the address of 'val' is passed to 'read_reg' here}}

  if (ret < 0) {
    _printk("failed, val %u\n", val); // expected-warning {{'val' is read here, but on this path 'read_reg' has failed and has not written to it (experimental check 'uninit-output')}}
    return ret;
  }
  return val;
}

int out_warn(struct dev *d) {
  u32 val;
  int ret = read_reg(d, &val); // expected-note {{the address of 'val' is passed to 'read_reg' here}}

  if (unlikely(ret))
    _printk("oops\n");
  return val; // expected-warning {{'val' is read here, but on this path 'read_reg' has failed and has not written to it (experimental check 'uninit-output')}}
}

// The callee is void and has an early return.
static void buf_read(struct dev *d, size_t count, void *output) {
  if (d->cached) {
    _printk("invalid\n");
    return; // expected-note {{'buf_read' returns here without having written through 'output'}}
  }
  memcpy(output, d->buf, count);
}

u8 buf_read_u8(struct dev *d) {
  u8 value;

  buf_read(d, sizeof(value), &value); // expected-note {{the address of 'value' is passed to 'buf_read' here}}
  return value; // expected-warning {{'value' is read here, but 'buf_read' can return without writing to it (experimental check 'uninit-output')}}
}

// A size of zero means that nothing is wanted.  The caller knows what it
// passes.
static int exec_cmd(struct dev *d, size_t out_len, u8 *out) {
  int ret = xfer(d, d->buf);

  if (ret)
    return ret;
  if (out_len)
    memcpy(out, d->buf, out_len);
  return 0; // expected-note {{'exec_cmd' returns here without having written through 'out'}}
}

int out_sized(struct dev *d) {
  u8 rc;
  int ret = exec_cmd(d, sizeof(rc), &rc);

  if (ret)
    return ret;
  return rc;
}

int out_sized_variable(struct dev *d, size_t n) {
  u8 rc;
  int ret = exec_cmd(d, n, &rc);

  if (ret)
    return ret;
  return rc;
}

int out_sized_zero(struct dev *d) {
  u8 rc;
  int ret = exec_cmd(d, 0, &rc); // expected-note {{the address of 'rc' is passed to 'exec_cmd' here}}

  if (ret)
    return ret;
  return rc; // expected-warning {{'rc' is read here, but 'exec_cmd' can return 0 without writing to it (experimental check 'uninit-output')}}
}

// The other output says that there is nothing to look at.
static int fdb_read(struct dev *d, u16 *vid, u16 *mask) {
  if (!d->cached) {
    *mask = 0;
    return 0;
  }
  *vid = d->buf[0];
  *mask = d->buf[1];
  return 0;
}

int out_other(struct dev *d) {
  u16 vid, mask;
  int ret = fdb_read(d, &vid, &mask);

  if (ret)
    return ret;
  if (mask)
    return vid;
  return 0;
}

// The callee can return 0 without writing.
static int maybe_get(struct dev *d, u32 *val) {
  if (d->cached)
    *val = d->cache;
  return 0; // expected-note {{'maybe_get' returns here without having written through 'val'}}
}

int out_success_unwritten(struct dev *d) {
  u32 val;
  int ret = maybe_get(d, &val); // expected-note {{the address of 'val' is passed to 'maybe_get' here}}

  if (ret)
    return ret;
  return val; // expected-warning {{'val' is read here, but 'maybe_get' can return 0 without writing to it (experimental check 'uninit-output')}}
}

// The callee always writes.
static int always(struct dev *d, u32 *val) {
  int ret = xfer(d, d->buf);

  *val = ret < 0 ? 0 : d->buf[0];
  return ret;
}

int out_always(struct dev *d) {
  u32 val;

  always(d, &val);
  return val;
}

// The callee hands the pointer to a function without a body.
int fill(struct dev *d, u32 *val);
static int hands_on(struct dev *d, u32 *val) {
  if (!d->regs)
    return -ENODEV; // expected-note {{'hands_on' returns here without having written through 'val'}}
  return fill(d, val);
}

int out_hands_on(struct dev *d) {
  u32 val;

  hands_on(d, &val); // expected-note {{the address of 'val' is passed to 'hands_on' here}}
  return val; // expected-warning {{'val' is read here, but 'hands_on' does not write to it when it fails, and the result of the call is not tested (experimental check 'uninit-output')}}
}

// A wrapper passes the summary of the function behind it on.
static int wrapper(struct dev *d, u32 *val) {
  return read_reg(d, val); // expected-note {{'wrapper' returns here without having written through 'val'}}
}

int out_wrapper(struct dev *d) {
  u32 val;

  wrapper(d, &val); // expected-note {{the address of 'val' is passed to 'wrapper' here}}
  return val; // expected-warning {{'val' is read here, but 'wrapper' does not write to it when it fails, and the result of the call is not tested (experimental check 'uninit-output')}}
}

static int wrapper2(struct dev *d, u32 *val) {
  int ret;

  ret = read_reg(d, val);
  if (ret)
    _printk("failed\n");
  return ret; // expected-note {{'wrapper2' returns here without having written through 'val'}}
}

int out_wrapper2(struct dev *d) {
  u32 val;
  int err = wrapper2(d, &val);

  if (err)
    return err;
  return val;
}

int out_wrapper2_bad(struct dev *d) {
  u32 val;

  wrapper2(d, &val); // expected-note {{the address of 'val' is passed to 'wrapper2' here}}
  return val; // expected-warning {{'val' is read here, but 'wrapper2' does not write to it when it fails, and the result of the call is not tested (experimental check 'uninit-output')}}
}

// A loop that fills an array is taken to run.
static int read_many(struct dev *d, u32 *vals, int n) {
  int i;

  for (i = 0; i < n; i++)
    vals[i] = d->buf[i];
  return 0;
}

int out_loop(struct dev *d) {
  u32 val;

  read_many(d, &val, 1);
  return val;
}

// A search that fails returns an error.
static int find(struct dev *d, int id, u32 *val) {
  int i;

  for (i = 0; i < 8; i++)
    if (d->buf[i] == id) {
      *val = i;
      return 0;
    }
  return -ENOENT; // expected-note {{'find' returns here without having written through 'val'}}
}

int out_find_ok(struct dev *d) {
  u32 val;

  if (find(d, 3, &val))
    return -1;
  return val;
}

int out_find_bad(struct dev *d) {
  u32 val;

  find(d, 3, &val); // expected-note {{the address of 'val' is passed to 'find' here}}
  return val; // expected-warning {{'val' is read here, but 'find' does not write to it when it fails, and the result of the call is not tested (experimental check 'uninit-output')}}
}

// The variable is written before.
int out_preset(struct dev *d) {
  u32 val;

  val = 0;
  read_reg(d, &val);
  return val;
}

// A call in a loop: the turn before has written the variable, the first
// turn has not.
u32 out_in_loop(struct dev *d, int n) {
  u32 val, sum = 0;
  int i;

  for (i = 0; i < n; i++) {
    read_reg(d, &val); // expected-note {{the address of 'val' is passed to 'read_reg' here}}
    sum += val; // expected-warning {{'val' is read here, but 'read_reg' does not write to it when it fails, and the result of the call is not tested (experimental check 'uninit-output')}}
  }
  return sum;
}

u32 out_in_loop_tested(struct dev *d, int n) {
  u32 val, sum = 0;
  int i;

  for (i = 0; i < n; i++) {
    if (read_reg(d, &val))
      break;
    sum += val;
  }
  return sum;
}

// Written on one of two ways to the call.
int out_one_way(struct dev *d) {
  u32 val;

  if (d->cached)
    val = d->cache;
  read_reg(d, &val); // expected-note {{the address of 'val' is passed to 'read_reg' here}}
  return val; // expected-warning {{'val' is read here, but 'read_reg' does not write to it when it fails, and the result of the call is not tested (experimental check 'uninit-output')}}
}

// The callee tests a sum of two parameters, and the call gives both.
static void read_cfg(struct dev *d, int where, int size, u32 *val) {
  if (where + size <= 8)
    *val = d->cache;
  else
    _printk("beyond the end\n");
} // expected-note {{'read_cfg' returns here without having written through 'val'}}

u32 out_sum_fits(struct dev *d) {
  u32 val;

  read_cfg(d, 4, 2, &val);
  return val;
}

u32 out_sum_too_large(struct dev *d) {
  u32 val;

  read_cfg(d, 8, 2, &val); // expected-note {{the address of 'val' is passed to 'read_cfg' here}}
  return val; // expected-warning {{'val' is read here, but 'read_cfg' can return without writing to it (experimental check 'uninit-output')}}
}

// The path on which the call has failed ends where the pointer that it
// returned is dereferenced, here or first thing in a function that is
// given it.
static struct dev *pick(struct dev *d, u32 *off) {
  if (!d->cached)
    return NULL; // expected-note {{'pick' returns here without having written through 'off'}}
  *off = d->cache;
  return d;
}

static bool usable(const struct dev *d) {
  return !d->cached;
}

u32 out_null_goes_to_callee(struct dev *d) {
  u32 off;
  struct dev *o = pick(d, &off);

  if (!usable(o))
    return 0;
  return off;
}

u32 out_null_is_dereferenced(struct dev *d) {
  u32 off;
  struct dev *o = pick(d, &off);

  if (o->cached)
    return 0;
  return off;
}

u32 out_null_goes_on(struct dev *d) {
  u32 off;
  struct dev *o = pick(d, &off); // expected-note {{the address of 'off' is passed to 'pick' here}}

  consume(o != NULL);
  return off; // expected-warning {{'off' is read here, but on this path 'pick' has failed and has not written to it (experimental check 'uninit-output')}}
}

// The status is assigned in the condition that tests it, and tested again
// at the label: it is not zero there.
static int find_head(struct dev *d, u32 *val) {
  int error;

  if ((error = use(1)))
    goto out;
  if ((error = use(2)) < 0)
    goto out;
  *val = d->cache;
  return 0;
out:
  if (error)
    _printk("failed\n");
  return error;
}

u32 out_assigned_in_condition(struct dev *d) {
  u32 val;

  if (find_head(d, &val))
    return 0;
  return val;
}

// The function that is given the variable is given the pointer as well that
// is NULL when the variable was not written.
static struct dev *ref_lock(struct dev *d, unsigned long *flags) {
  if (!d->cached)
    return NULL;
  *flags = d->cache;
  return d;
}

void unlock_deref(struct dev *d, unsigned long flags);

void out_with_its_pointer(struct dev *d) {
  unsigned long flags;
  struct dev *o = ref_lock(d, &flags);

  if (o)
    consume(o->cache);
  unlock_deref(o, flags);
}

// "err ? ERR_PTR(err) : NULL" is an error or nothing, whatever the sign of
// err.
static struct dev *search(struct dev *d, u32 *val) {
  int err = use(1);

  if (err || !d->cached)
    return err ? ERR_PTR(err) : NULL;
  *val = d->cache;
  return d;
}

u32 out_err_ptr_or_null(struct dev *d) {
  u32 val;
  struct dev *o = search(d, &val);

  if (IS_ERR_OR_NULL(o))
    return 0;
  return val;
}

// bool: false is the failure.
static bool parse(const char *s, int *out) {
  if (!s[0])
    return false; // expected-note {{'parse' returns here without having written through 'out'}}
  *out = s[0] - '0';
  return true;
}

int out_bool_ok(const char *s) {
  int n;

  if (!parse(s, &n))
    return -EINVAL;
  return n;
}

int out_bool_bad(const char *s) {
  int n;
  bool ok = parse(s, &n); // expected-note {{the address of 'n' is passed to 'parse' here}}

  if (!ok)
    _printk("bad %d\n", n); // expected-warning {{'n' is read here, but on this path 'parse' has failed and has not written to it (experimental check 'uninit-output')}}
  return ok ? n : 0;
}

// The message on the failure path.
static int check_stats(struct dev *d, const char **errmsg) {
  void *p = d->regs;

  if (IS_ERR(p))
    return PTR_ERR(p); // expected-note {{'check_stats' returns here without having written through 'errmsg'}}
  if (!d->cached) {
    *errmsg = "not cached";
    return -EINVAL;
  }
  return 0;
}

int out_errmsg(struct dev *d) {
  const char *errmsg;
  int err = check_stats(d, &errmsg); // expected-note {{the address of 'errmsg' is passed to 'check_stats' here}}

  if (err) {
    _printk("%s\n", errmsg); // expected-warning {{'errmsg' is read here, but on this path 'check_stats' has failed and has not written to it (experimental check 'uninit-output')}}
    return err;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// null-argument

struct pkt {
  int type;
};

static int handle_error(struct dev *d, struct pkt *pkt) {
  _printk("error of type %d\n", pkt->type); // expected-note {{'pkt' is dereferenced here}}
  d->cached = 0;
  return 0;
}

static int handle_checked(struct dev *d, struct pkt *pkt) {
  if (pkt)
    _printk("error of type %d\n", pkt->type);
  return 0;
}

int null_argument(struct dev *d) {
  handle_checked(d, NULL);
  return handle_error(d, NULL); // expected-warning {{NULL is passed for parameter 2 of 'handle_error', which dereferences it without a test (experimental check 'null-argument')}}
}

// ---------------------------------------------------------------------------
// error-pointer-null-test

void *get_thing(struct dev *d);
void put_thing(void *);

int null_test_of_error(struct dev *d) {
  void *t = get_thing(d);
  int ret = 0;

  if (IS_ERR(t)) { // expected-note {{tested here}}
    ret = PTR_ERR(t);
    goto out;
  }
  ret = use(1);
out:
  if (t)
// expected-warning@-1 {{'t' is tested for NULL here, but on this path it holds an error pointer, which the test takes for a valid pointer and lets through to where it is used (experimental check 'error-pointer-null-test')}}
    put_thing(t); // expected-note {{the error pointer is used here}}
  return ret;
}

int null_test_reset(struct dev *d) {
  void *t = get_thing(d);
  int ret = 0;

  if (IS_ERR(t)) {
    ret = PTR_ERR(t);
    t = NULL;
    goto out;
  }
  ret = use(1);
out:
  if (t)
    put_thing(t);
  return ret;
}

int null_test_or_null(struct dev *d) {
  void *t = get_thing(d);
  int ret = 0;

  if (IS_ERR(t)) {
    ret = PTR_ERR(t);
    goto out;
  }
  ret = use(1);
out:
  if (!IS_ERR_OR_NULL(t))
    put_thing(t);
  return ret;
}

// ---------------------------------------------------------------------------
// container-of-null

struct list_head {
  struct list_head *next, *prev;
};
#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) \
  list_entry((ptr)->next, type, member)
#define list_next_entry(pos, member) \
  list_entry((pos)->member.next, typeof(*(pos)), member)
#define list_entry_is_head(pos, head, member) (&pos->member == (head))
#define list_for_each_entry(pos, head, member) \
  for (pos = list_first_entry(head, typeof(*pos), member); \
       !list_entry_is_head(pos, head, member); \
       pos = list_next_entry(pos, member))
#define list_first_entry_or_null(ptr, type, member) ({ \
  struct list_head *head__ = (ptr); \
  struct list_head *pos__ = head__->next; \
  pos__ != head__ ? list_entry(pos__, type, member) : NULL; \
})

struct item {
  int id;
  struct list_head list;
};

struct first {
  struct list_head list;
  int id;
};

struct work {
  int pending;
};

struct info {
  int a;
  struct work tx_work;
};

struct lead {
  struct work work;
  int a;
};

int first_entry(struct list_head *head) {
  struct item *it = list_first_entry(head, struct item, list); // expected-note {{'it' gets its value here}}

  if (!it)
// expected-warning@-1 {{'it' is tested for NULL, but list_first_entry() never yields NULL: for an empty list, or behind the last entry, it is a pointer computed from the list head (experimental check 'container-of-null')}}
    return -ENOENT;
  return it->id;
}

int first_entry_or_null(struct list_head *head) {
  struct item *it = list_first_entry_or_null(head, struct item, list);

  if (!it)
    return -ENOENT;
  return it->id;
}

int after_loop(struct list_head *head, int id) {
  struct item *pos;

  list_for_each_entry(pos, head, list)
// expected-note@-1 {{'pos' gets its value here}}
// expected-note@-2 {{the loop ends here if nothing has left it before}}
    if (pos->id == id)
      break;
  if (!pos)
// expected-warning@-1 {{'pos' is tested for NULL, but list_for_each_entry() never yields NULL: for an empty list, or behind the last entry, it is a pointer computed from the list head (experimental check 'container-of-null')}}
    return -ENOENT;
  return pos->id;
// expected-warning@-1 {{'pos' is dereferenced here, but on this path the loop over the list has run to its end, which leaves 'pos' at the head of the list, taken for an entry (experimental check 'cursor-past-end')}}
}

int after_loop_found(struct list_head *head, int id) {
  struct item *pos, *found = NULL;

  list_for_each_entry(pos, head, list)
    if (pos->id == id) {
      found = pos;
      break;
    }
  if (!found)
    return -ENOENT;
  return found->id;
}

int member_at_zero(struct list_head *head) {
  struct first *f = list_first_entry(head, struct first, list); // expected-note {{'f' gets its value here}}

  if (f == NULL)
// expected-warning@-1 {{'f' is tested for NULL, but list_first_entry() never yields NULL: for an empty list, or behind the last entry, it is a pointer computed from the list head (experimental check 'container-of-null')}}
    return -ENOENT;
  return f->id;
}

void tx_work(struct work *work) {
  struct info *info = container_of(work, struct info, tx_work); // expected-note {{'info' gets its value here}}

  if (info)
// expected-warning@-1 {{'info' is tested for NULL, but it comes from container_of() with the member at offset 4, so it is not NULL even if the pointer it was computed from is (experimental check 'container-of-null')}}
    info->a = 1;
}

void lead_work(struct work *work) {
  struct lead *lead = container_of(work, struct lead, work);

  if (lead)
    lead->a = 1;
}

void reassigned(struct work *work, struct info *other) {
  struct info *info = container_of(work, struct info, tx_work);

  if (work->pending)
    info = other;
  if (info)
    info->a = 1;
}

// ---------------------------------------------------------------------------
// direct-return

int clk_prepare_enable(struct clk *);
int clk_enable(struct clk *);
void clk_disable(struct clk *);
void clk_disable_unprepare(struct clk *);
int setup_a(struct dev *);
int setup_b(struct dev *);
void *kmalloc(size_t, int);
void mutex_lock(void *);
void mutex_unlock(void *);

int direct_return(struct dev *d) {
  int ret;

  ret = clk_prepare_enable(d->clk);
  if (ret)
    return ret;
  ret = setup_a(d);
  if (ret)
    goto err_disable; // expected-note {{an earlier error path unwinds here}}
  if (!d->regs)
    return -ENODEV;
// expected-warning@-1 {{this error path returns directly, but the error paths before and after it jump to 'err_disable' to undo what the function has done (experimental check 'direct-return')}}
  ret = setup_b(d);
  if (ret)
    goto err_disable; // expected-note {{a later error path unwinds here}}
  return 0;

err_disable:
  clk_disable_unprepare(d->clk);
  return ret;
}

int direct_return_released(struct dev *d, void *lock) {
  int ret;

  mutex_lock(lock);
  ret = setup_a(d);
  if (ret)
    goto unlock;
  mutex_unlock(lock);
  if (!d->regs)
    return -ENODEV;
  mutex_lock(lock);
  ret = setup_b(d);
  if (ret)
    goto unlock;
  ret = 0;
unlock:
  mutex_unlock(lock);
  return ret;
}

int direct_return_cleans(struct dev *d) {
  int ret;

  ret = clk_prepare_enable(d->clk);
  if (ret)
    return ret;
  ret = setup_a(d);
  if (ret)
    goto err_disable;
  if (!d->regs) {
    clk_disable_unprepare(d->clk);
    return -ENODEV;
  }
  ret = setup_b(d);
  if (ret)
    goto err_disable;
  return 0;

err_disable:
  clk_disable_unprepare(d->clk);
  return ret;
}

int direct_return_switch(struct dev *d, int mode) {
  int ret;
  void *buf = kmalloc(16, 0);

  if (!buf)
    return -ENOMEM;
  ret = setup_a(d);
  if (ret)
    goto free; // expected-note {{an earlier error path unwinds here}}
  switch (mode) {
  case 0:
    d->cached = 0;
    break;
  case 1:
    d->cached = 1;
    break;
  default:
    _printk("invalid mode %d\n", mode);
    return -EINVAL;
// expected-warning@-1 {{this error path returns directly, but the error paths before and after it jump to 'free' to undo what the function has done (experimental check 'direct-return')}}
  }
  ret = setup_b(d);
  if (ret)
    goto free; // expected-note {{a later error path unwinds here}}
  ret = 0;
free:
  kfree(buf);
  return ret;
}

int direct_return_success(struct dev *d) {
  int ret;

  ret = clk_prepare_enable(d->clk);
  if (ret)
    return ret;
  ret = setup_a(d);
  if (ret)
    goto err_disable;
  if (!d->regs)
    return 0;
  ret = setup_b(d);
  if (ret)
    goto err_disable;
  return 0;

err_disable:
  clk_disable_unprepare(d->clk);
  return ret;
}

// A fallback label is another way to succeed.
int direct_return_fallback(struct dev *d, u32 *val) {
  if (!d->regs)
    goto fallback;
  if (d->cached)
    return -EINVAL;
  if (setup_a(d))
    goto fallback;
  *val = 1;
  return 0;

fallback:
  consume(0);
  *val = 0;
  return 0;
}

// What the return has just failed to get is what the label would free.
void *again(struct dev *d, void *path);
void free_path(void *path);

int direct_return_same(struct dev *d) {
  void *path = NULL;
  int ret = 0;

  path = again(d, path);
  if (IS_ERR(path)) {
    ret = PTR_ERR(path);
    goto out;
  }
  path = again(d, path);
  if (IS_ERR(path))
    return PTR_ERR(path);
  ret = setup_b(d);
  if (ret)
    goto out;
  ret = 0;
out:
  free_path(path);
  return ret;
}

// ---------------------------------------------------------------------------
// error-pointer-null-test: the other shapes

void pci_disable(struct dev *d);
void set_version(struct dev *d);
void *splice(void *t, struct dev *d);

// The NULL test is the only thing that looks at the error pointer.
int null_test_only(struct dev *d) {
  void *t = NULL;
  int err;

  err = setup_a(d);
  if (err)
    goto err_out;
  t = get_thing(d);
  if (IS_ERR(t)) { // expected-note {{tested here}}
    err = PTR_ERR(t);
    goto err_out;
  }
  return 0;

err_out:
  if (!t)
// expected-warning@-1 {{'t' is tested for NULL here, but on this path it holds an error pointer, which the test takes for a valid pointer, and nothing else looks at it (experimental check 'error-pointer-null-test')}}
    pci_disable(d);
  return err;
}

// The error pointer is handed on behind the test: three states on purpose.
void *null_test_three_states(struct dev *d) {
  void *t = get_thing(d);

  if (IS_ERR(t) || d->cached)
    goto out;
  consume(1);
out:
  if (!t)
    set_version(d);
  return splice(t, d);
}

// ---------------------------------------------------------------------------
// a test of a value that is promoted

struct two {
  u16 type;
  u16 depth;
};
struct two get_two(struct dev *d);

static u16 get_depth(struct dev *d, int *depth) {
  struct two res = get_two(d);

  if (depth && res.type)
    *depth = res.depth;
  return res.type; // expected-note {{'get_depth' returns here without having written through 'depth'}}
}

int promoted(struct dev *d) {
  int depth;
  u16 type = get_depth(d, &depth);

  if (type)
    return depth;
  return 0;
}

int promoted_bad(struct dev *d) {
  int depth;

  get_depth(d, &depth); // expected-note {{the address of 'depth' is passed to 'get_depth' here}}
  return depth; // expected-warning {{'depth' is read here, but 'get_depth' can return 0 without writing to it (experimental check 'uninit-output')}}
}

// ---------------------------------------------------------------------------
// unwind-far, unwind-return-call

struct priv {
  struct clk *clk;
  void *base;
  int irq;
};
void *of_iomap(void *np, int index);
void iounmap(void *);
int register_it(struct priv *);
int get_irq(struct priv *);

static int far_probe(struct priv *priv, void *np) {
  int irq;

  priv->base = of_iomap(np, 0); // expected-note {{acquired here}}
  if (!priv->base)
    return -ENOMEM;
  irq = get_irq(priv);
  if (irq < 0)
    return irq; // expected-warning {{'priv->base' was acquired with of_iomap() and this error path returns without iounmap(), which 'far_remove' calls for it (experimental check 'unwind-far')}}
  priv->irq = irq;
  return 0;
}

static void far_remove(struct priv *priv) {
  iounmap(priv->base); // expected-note {{another path releases it here}}
}

struct ops {
  int (*probe)(struct priv *, void *);
  void (*remove)(struct priv *);
};
const struct ops far_ops = {
  .probe = far_probe,
  .remove = far_remove,
};

// The caller cleans up after it.
static int near_init(struct priv *priv, void *np) {
  priv->base = of_iomap(np, 1);
  if (!priv->base)
    return -ENOMEM;
  if (get_irq(priv) < 0)
    return -ENODEV;
  return 0;
}

static void near_exit(struct priv *priv) {
  iounmap(priv->base);
}

int near_probe(struct priv *priv, void *np) {
  int ret = near_init(priv, np);

  if (ret) {
    near_exit(priv);
    return ret;
  }
  return 0;
}

int return_call(struct priv *priv) {
  int ret;

  ret = clk_prepare_enable(priv->clk); // expected-note {{acquired here}}
  if (ret)
    return ret;
  ret = get_irq(priv);
  if (ret < 0)
    goto err_disable;
  return register_it(priv);
// expected-warning@-1 {{'priv->clk' was acquired with clk_prepare_enable() and is still held if 'register_it' fails and this return passes the error on, although other error paths call clk_disable_unprepare() (experimental check 'unwind-return-call')}}

err_disable:
  clk_disable_unprepare(priv->clk); // expected-note {{another path releases it here}}
  return ret;
}

int return_status(struct priv *priv) {
  int ret;

  ret = clk_prepare_enable(priv->clk); // expected-note {{acquired here}}
  if (ret)
    return ret;
  ret = get_irq(priv);
  if (ret < 0)
    goto err_disable;
  ret = register_it(priv);
  return ret;
// expected-warning@-1 {{'priv->clk' was acquired with clk_prepare_enable() and is still held if the call that set 'ret' fails and this return passes the error on, although other error paths call clk_disable_unprepare() (experimental check 'unwind-return-call')}}

err_disable:
  clk_disable_unprepare(priv->clk); // expected-note {{another path releases it here}}
  return ret;
}

// ---------------------------------------------------------------------------
// error-deref-path

struct core {
  int base;
  int rev;
};
void *kzalloc(size_t, int);

static struct core *add_core(struct dev *d, int id) {
  struct core *core = kzalloc(sizeof(*core), 0);

  if (!core)
    return ERR_PTR(-ENOMEM);
  core->base = id;
  return core;
}

static void core_rev(struct dev *d, struct core *core) {
  core->rev = d->cached + core->base; // expected-note {{'core' is dereferenced here}}
}

int recognition(struct dev *d, int soc) {
  struct core *core;

  if (soc == 1) {
    core = add_core(d, 1); // expected-note {{the value is assigned here}}
    core_rev(d, core);
// expected-warning@-1 {{'core' is passed to 'core_rev', which dereferences it, but it is the result of 'add_core', which returns an error pointer on failure, and this path has not tested it (experimental check 'error-deref-path')}}
    core = add_core(d, 2);
    core_rev(d, core);
  } else {
    core = add_core(d, 3);
    if (IS_ERR(core))
      return PTR_ERR(core);
    core_rev(d, core);
  }
  return 0;
}

int recognition_direct(struct dev *d) {
  struct core *core = add_core(d, 1); // expected-note {{the value is assigned here}}

  return core->rev;
// expected-warning@-1 {{'core' is dereferenced here, but it is the result of 'add_core', which returns an error pointer on failure, and this path has not tested it (experimental check 'error-deref-path')}}
}

// ---------------------------------------------------------------------------
// The trap of WARN_ON() is inline assembly.  It does not change the
// condition that was just tested.

#define WARN_ON_TRAP(condition) ({ \
  int __ret_warn_on = !!(condition); \
  if (unlikely(__ret_warn_on)) \
    __asm__ volatile(""); \
  unlikely(__ret_warn_on); \
})

int out_warn_on(struct dev *d) {
  u32 val;

  if (WARN_ON_TRAP(read_reg(d, &val)))
    return -EIO;
  return val;
}

// ---------------------------------------------------------------------------
// What the path search knows about a value.

// "int ret = PTR_ERR(p);" keeps the sign.
struct thing_group {
  int id;
};
struct thing_group *make_group(struct dev *d);
int attach_group(struct thing_group *g);
int attach_item(struct dev *d);

int narrowed_errno(struct dev *d) {
  struct thing_group *group = make_group(d);
  int ret = 0;

  if (!group)
    group = ERR_PTR(-ENOMEM);
  if (IS_ERR(group))
    ret = PTR_ERR(group);
  if (ret)
    return ret;
  if (group)
    ret = attach_group(group);
  else
    ret = attach_item(d);
  return ret;
}

// A function that compares its argument with a constant is evaluated.
enum bfs_result { BFS_EINVALIDNODE = -2, BFS_EQUEUEFULL = -1, BFS_RMATCH = 0,
                  BFS_RNOMATCH = 1 };
static inline bool bfs_error(enum bfs_result res) {
  return res < 0;
}

static enum bfs_result find_usage(struct dev *d, u32 *target) {
  if (!d->regs)
    return BFS_EINVALIDNODE;
  if (!d->cached)
    return BFS_RNOMATCH; // expected-note {{'find_usage' returns here without having written through 'target'}}
  *target = d->cache;
  return BFS_RMATCH;
}

int predicate(struct dev *d) {
  u32 target;
  enum bfs_result ret = find_usage(d, &target);

  if (bfs_error(ret))
    return 0;
  if (ret == BFS_RNOMATCH)
    return 1;
  return target;
}

int predicate_missing(struct dev *d) {
  u32 target;
  enum bfs_result ret = find_usage(d, &target); // expected-note {{the address of 'target' is passed to 'find_usage' here}}

  if (bfs_error(ret))
    return 0;
  return target; // expected-warning {{'target' is read here, but 'find_usage' can return 1 without writing to it (experimental check 'uninit-output')}}
}

// The result is compared with the one value that says "nothing written".
static int find_slot(struct dev *d, struct dev **pool) {
  if (!d->cached)
    return -1;
  *pool = d;
  return d->cache;
}

int exact_value(struct dev *d) {
  struct dev *pool;
  int index = find_slot(d, &pool);

  if (index == -1)
    return -ENOMEM;
  return pool->cached + index;
}

// Another output of the same call says whether this one was written.
struct lruvec;
void unlock_lruvec(struct lruvec *l, unsigned long flags);
static void release_it(struct dev *d, struct lruvec **lruvecp,
                       unsigned long *flagsp) {
  if (d->cached) {
    *lruvecp = d->regs;
    *flagsp = 1;
  }
}

void sibling_output(struct dev *d) {
  struct lruvec *lruvec = NULL;
  unsigned long flags;

  release_it(d, &lruvec, &flags);
  if (lruvec)
    unlock_lruvec(lruvec, flags);
}

// A count that the caller passes through a pointer.
static int copy_in(unsigned int *count, const void **buf, void *data) {
  if (*count == 0)
    return 0;
  memcpy(data, *buf, *count);
  return 0;
}

int through_pointer(const void *buf, unsigned int count) {
  u32 val;
  int r;

  if (count != sizeof(val))
    return -EINVAL;
  r = copy_in(&count, &buf, &val);
  if (r)
    return r;
  return val;
}

// ---------------------------------------------------------------------------
// direct-return: a label that is another way to do the work

int submit_sync(struct dev *d);
int submit_async(struct dev *d, void *src);
int wait_io(struct dev *d);

int other_way(struct dev *d) {
  void *src;
  int ret;

  if (!d->regs)
    goto sync_io;
  src = kmalloc(16, 0);
  if (!src) {
    ret = wait_io(d);
    if (ret)
      return ret;
    src = kmalloc(16, 0);
    if (!src)
      goto sync_io;
  }
  return submit_async(d, src);
sync_io:
  return submit_sync(d);
}

// error-deref-path: the function that is given the result may test it.
struct name {
  const char *name;
};
int lookup(struct dev *d, struct name *name);

static struct name *get_name(struct dev *d) {
  struct name *name = kzalloc(sizeof(*name), 0);

  if (!name)
    return ERR_PTR(-ENOMEM);
  return name;
}

int tested_by_callee(struct dev *d) {
  struct name *name = get_name(d);
  int error = lookup(d, name);

  if (error)
    return error;
  return name->name[0];
}

// direct-return: the buffer goes to the caller before the return.
struct split {
  void *ib;
};
void *kvzalloc(size_t, int);
void kvfree(const void *);
int ib_read(struct dev *d, void *ib);
int ib_write(struct dev *d, void *ib);

int handed_over(struct dev *d, struct split *si) {
  void *ib = kvzalloc(64, 0);
  int err;

  if (!ib)
    return -ENOMEM;
  err = ib_read(d, ib);
  if (err)
    goto err_out;
  if (d->cached) {
    si->ib = ib;
    return -EINVAL;
  }
  err = ib_write(d, ib);
  if (err)
    goto err_out;
  err = 0;
err_out:
  kvfree(ib);
  return err;
}

// direct-return: code that the configuration has switched off.
#define IS_OFF 0
#define SET_MSG(d) do { (d)->cache = 1; } while (0)

int switched_off(struct dev *d) {
  int err = setup_a(d);

  if (err)
    return err;
  if (IS_OFF) {
    SET_MSG(d);
    return -EINVAL;
  }
  if (d->cached) {
    void *buf = kmalloc(8, 0);

    if (!buf) {
      err = -ENOMEM;
      goto err;
    }
    err = setup_b(d);
    kfree(buf);
    if (err)
      goto err;
  }
  return 0;
err:
  clk_disable_unprepare(d->clk);
  return err;
}

// unwind-return-call: the call that acquires is the one that is returned.
int event(struct priv *priv, int on) {
  if (on)
    return clk_prepare_enable(priv->clk);
  clk_disable_unprepare(priv->clk);
  return 0;
}

// unwind-far: a function that takes and gives back is not the one that
// tears down, and a destructor that is registered runs when this one fails.
struct card {
  void (*private_free)(struct card *);
  struct priv *priv;
};
int request_firmware(const void **fw, const char *name, void *dev);
void release_firmware(const void *fw);
struct chip {
  const void *image;
  struct clk *clk;
};

static void chip_free(struct card *card);

static int chip_create(struct card *card, struct chip *chip) {
  int err;

  card->private_free = chip_free;
  err = request_firmware(&chip->image, "image", card);
  if (err < 0)
    return err;
  if (get_irq(card->priv) < 0)
    return -ENODEV;
  return 0;
}

static struct chip the_chip;
static void chip_free(struct card *card) {
  release_firmware(the_chip.image);
}

int chip_probe(struct card *card) {
  return chip_create(card, &the_chip);
}

static int chip_set_rate(struct chip *chip) {
  int ret = clk_enable(chip->clk);

  if (ret)
    return ret;
  if (!chip->image)
    return -EINVAL;
  return 0;
}

static int chip_measure(struct chip *chip) {
  int ret = clk_enable(chip->clk);

  if (ret)
    return ret;
  clk_disable(chip->clk);
  return 0;
}

int (*const chip_ops[])(struct chip *) = { chip_set_rate, chip_measure };

// ---------------------------------------------------------------------------
// The code before the first branch of a function goes on behind a branch
// that the configuration has decided, as every logging macro has one.

#define log_it(d, fmt, ...) do { \
  if (__builtin_constant_p(fmt)) \
    (d)->cache = sizeof(fmt); \
  _printk(fmt, ##__VA_ARGS__); \
} while (0)

static int system_error(struct dev *d, struct pkt *pkt) {
  log_it(d, "received system error of type %d\n", pkt->type); // expected-note {{'pkt' is dereferenced here}}
  d->cached = 0;
  return 0;
}

int null_behind_macro(struct dev *d) {
  return system_error(d, NULL); // expected-warning {{NULL is passed for parameter 2 of 'system_error', which dereferences it without a test (experimental check 'null-argument')}}
}

// ---------------------------------------------------------------------------
// unwind-far for a status that is handed on: the last call of probe fails.

int request_irq(unsigned int irq, void *handler, unsigned long flags,
                const char *name, void *dev);
void free_irq(unsigned int irq, void *dev);
int register_component(struct priv *priv);

struct client {
  unsigned int irq;
  struct priv *priv;
};

static int codec_probe(struct client *client) {
  int ret;

  ret = request_irq(client->irq, NULL, 0, "codec", client); // expected-note {{acquired here}}
  if (ret)
    return ret;
  ret = register_component(client->priv);
  return ret;
// expected-warning@-1 {{'client->irq' was acquired with request_irq() and is still held if the call that set 'ret' fails and this return passes the error on: only 'codec_remove' calls free_irq() for it (experimental check 'unwind-far')}}
}

static void codec_remove(struct client *client) {
  free_irq(client->irq, client); // expected-note {{another path releases it here}}
}

struct client_ops {
  int (*probe)(struct client *);
  void (*remove)(struct client *);
};
const struct client_ops codec_ops = {
  .probe = codec_probe,
  .remove = codec_remove,
};

// ---------------------------------------------------------------------------
// unwind-far: a variable with a cleanup function that is declared behind the
// acquisition releases it at the end of its scope.

struct gphy {
  struct clk *clk;
  int ready;
};

static void gphy_clk_disable(struct gphy *g) {
  clk_disable_unprepare(g->clk); // expected-note {{another path releases it here}}
}

static inline void __free_gphy_clk(void *arg) {
  struct gphy *g = *(struct gphy **)arg;

  if (g)
    gphy_clk_disable(g);
}

int gphy_reset(struct gphy *g);

static int gphy_init(struct gphy *g) {
  int ret;

  ret = clk_prepare_enable(g->clk);
  if (ret)
    return ret;
  struct gphy *guard __attribute__((cleanup(__free_gphy_clk))) = g;

  ret = gphy_reset(g);
  if (ret)
    return ret;
  guard = NULL;
  g->ready = 1;
  return 0;
}

// The same without the variable.
static int gphy_init_bare(struct gphy *g) {
  int ret;

  ret = clk_prepare_enable(g->clk); // expected-note {{acquired here}}
  if (ret)
    return ret;
  ret = gphy_reset(g);
  if (ret)
    return ret;
// expected-warning@-1 {{'g->clk' was acquired with clk_prepare_enable() and this error path returns without clk_disable_unprepare(), which 'gphy_clk_disable' calls for it (experimental check 'unwind-far')}}
  g->ready = 1;
  return 0;
}

static void gphy_exit(struct gphy *g) {
  gphy_clk_disable(g);
}

struct gphy_ops {
  int (*init)(struct gphy *);
  void (*exit)(struct gphy *);
};
const struct gphy_ops gphy_ops = { .init = gphy_init, .exit = gphy_exit };
const struct gphy_ops gphy_bare_ops = { .init = gphy_init_bare, .exit = gphy_exit };

// ---------------------------------------------------------------------------
// uninit-output: the function writes for one error code and for no other,
// and the caller reads for that one alone.

#define ENOSPC 28
int try_fill(int n);

static int fill_some(int want, int *filled) {
  int err = 0, done = 0;

  if (want < 0) {
    err = -EINVAL;
    goto out;
  }
  while (done < want) {
    err = try_fill(done);
    if (err < 0)
      goto out;
    done++;
  }
  return 0;
out:
  if (err == -ENOSPC && filled)
    *filled = done;
  return err;
}

static int fill_wrapped(int want, int *filled) {
  return fill_some(want, filled); // expected-note {{'fill_wrapped' returns here without having written through 'filled'}}
}

int fill_and_use(int want) {
  int filled, err;

  err = fill_wrapped(want, &filled);
  if (err && err != -ENOSPC)
    return err;
  if (!err)
    return want;
  return filled;
}

// Read for the other errors.
int fill_and_misuse(int want) {
  int filled, err;

  err = fill_wrapped(want, &filled); // expected-note {{the address of 'filled' is passed to 'fill_wrapped' here}}
  if (!err)
    return want;
  if (err == -ENOSPC)
    return 0;
  return filled; // expected-warning {{'filled' is read here, but on this path 'fill_wrapped' has failed and has not written to it (experimental check 'uninit-output')}}
}

// ---------------------------------------------------------------------------
// unwind-far: devm_add_action_or_reset() is a macro in the kernel, and the
// function behind it has another name.

struct regulator;
int regulator_enable(struct regulator *r);
int regulator_disable(struct regulator *r);
int __devm_add_action_or_reset(void *dev, void (*action)(void *), void *data,
                               const char *name);
#define devm_add_action_or_reset(dev, action, data) \
  __devm_add_action_or_reset(dev, action, data, #action)

struct fan {
  struct regulator *power;
  void *dev;
};

static void fan_power_off(void *data) {
  regulator_disable(data);
}

static int fan_probe(struct fan *fan) {
  int ret;

  ret = regulator_enable(fan->power);
  if (ret)
    return ret;
  ret = devm_add_action_or_reset(fan->dev, fan_power_off, fan->power);
  if (ret)
    return ret;
  return 0;
}

static int fan_suspend(struct fan *fan) {
  return regulator_disable(fan->power);
}

struct fan_ops {
  int (*probe)(struct fan *);
  int (*suspend)(struct fan *);
};
const struct fan_ops fan_ops = { .probe = fan_probe, .suspend = fan_suspend };

