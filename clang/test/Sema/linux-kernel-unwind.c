// RUN: %clang_cc1 -fsyntax-only -ffreestanding \
// RUN:   -Wlinux-kernel-missing-unwind -verify=unwind %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-memory-leak \
// RUN:   -verify=leak %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wall -verify=wall %s

// wall-no-diagnostics

#define NULL ((void *)0)
#define EIO 5
#define ENOMEM 12
#define EINVAL 22

struct clk;
struct device;
struct mutex {
  int owner;
};

int clk_prepare_enable(struct clk *clk);
void clk_disable_unprepare(struct clk *clk);
void mutex_lock(struct mutex *lock);
void mutex_unlock(struct mutex *lock);
void *ioremap(unsigned long start, unsigned long size);
void iounmap(void *addr);
void *kzalloc(unsigned long size, unsigned int flags);
void kfree(const void *p);
int devm_add_action_or_reset(struct device *dev, void (*action)(void *),
                             void *data);
int setup(struct device *dev);

struct priv {
  struct device *dev;
  struct clk *clk;
  struct mutex lock;
  void *base;
  char *buf;
  int value;
};

void priv_teardown(struct priv *p);

// An error path that keeps what other paths release.

int missing(struct priv *p) {
  int ret;

  ret = clk_prepare_enable(p->clk); // unwind-note {{acquired here}}
  if (ret)
    return ret;
  ret = setup(p->dev);
  if (ret)
    return ret; // unwind-warning {{'p->clk' was acquired with clk_prepare_enable() and this error path returns without clk_disable_unprepare(), which other paths call}}
  ret = setup(p->dev);
  if (ret)
    goto err;
  return 0;
err:
  clk_disable_unprepare(p->clk); // unwind-note {{another path releases it here}}
  return ret;
}

int complete(struct priv *p) {
  int ret;

  ret = clk_prepare_enable(p->clk);
  if (ret)
    return ret;
  ret = setup(p->dev);
  if (ret)
    goto err;
  ret = setup(p->dev);
  if (ret)
    goto err;
  return 0;
err:
  clk_disable_unprepare(p->clk);
  return ret;
}

int tested_directly(struct priv *p) {
  if (clk_prepare_enable(p->clk)) // unwind-note {{acquired here}}
    return -EIO;
  if (setup(p->dev))
    return -EIO; // unwind-warning {{'p->clk' was acquired with clk_prepare_enable()}}
  if (setup(p->dev)) {
    clk_disable_unprepare(p->clk); // unwind-note {{another path releases it here}}
    return -EIO;
  }
  return 0;
}

// Released by a remove callback or by devres: this function never does.
int released_elsewhere(struct priv *p) {
  int ret;

  ret = clk_prepare_enable(p->clk);
  if (ret)
    return ret;
  ret = setup(p->dev);
  if (ret)
    return ret;
  return 0;
}

// "Disable, change, enable again": an error after the last step leaves the
// clock as the function found it.
int restart(struct priv *p) {
  int ret;

  clk_disable_unprepare(p->clk);
  p->value++;
  ret = clk_prepare_enable(p->clk);
  if (ret)
    return ret;
  ret = setup(p->dev);
  if (ret)
    return ret;
  return 0;
}

static void disable_action(void *data) { clk_disable_unprepare(data); }

int managed(struct priv *p) {
  int ret;

  ret = clk_prepare_enable(p->clk);
  if (ret)
    return ret;
  ret = devm_add_action_or_reset(p->dev, disable_action, p->clk);
  if (ret)
    return ret;
  ret = setup(p->dev);
  if (ret)
    return ret;
  if (p->value)
    clk_disable_unprepare(p->clk);
  return 0;
}

static void power_down(struct priv *p) { clk_disable_unprepare(p->clk); }

int released_by_helper(struct priv *p) {
  int ret;

  ret = clk_prepare_enable(p->clk);
  if (ret)
    return ret;
  ret = setup(p->dev);
  if (ret) {
    power_down(p);
    return ret;
  }
  ret = setup(p->dev);
  if (ret) {
    priv_teardown(p);
    return ret;
  }
  if (p->value)
    clk_disable_unprepare(p->clk);
  return 0;
}

// A success return keeps the resource: that is what the function is for.
int stays_enabled(struct priv *p) {
  int ret;

  ret = clk_prepare_enable(p->clk);
  if (ret)
    return ret;
  ret = setup(p->dev);
  if (ret) {
    clk_disable_unprepare(p->clk);
    return ret;
  }
  return 0;
}

// Locks.

int locked_return(struct priv *p, int value) {
  mutex_lock(&p->lock); // unwind-note {{acquired here}}
  if (value < 0)
    return -EINVAL; // unwind-warning {{'&p->lock' was acquired with mutex_lock() and this error path returns without mutex_unlock(), which other paths call}}
  p->value = value;
  mutex_unlock(&p->lock); // unwind-note {{another path releases it here}}
  return 0;
}

int unlocked_return(struct priv *p, int value) {
  int ret = 0;

  mutex_lock(&p->lock);
  if (value < 0) {
    ret = -EINVAL;
    goto out;
  }
  p->value = value;
out:
  mutex_unlock(&p->lock);
  return ret;
}

// A mapping that the result names.

int mapping(struct priv *p) {
  p->base = ioremap(0x1000, 0x100); // unwind-note {{acquired here}}
  if (!p->base)
    return -ENOMEM;
  if (setup(p->dev))
    return -EIO; // unwind-warning {{'p->base' was acquired with ioremap() and this error path returns without iounmap(), which other paths call}}
  if (setup(p->dev)) {
    iounmap(p->base); // unwind-note {{another path releases it here}}
    return -EIO;
  }
  return 0;
}

// A local allocation that is lost.

int leak(struct device *dev, unsigned long n) {
  char *buf = kzalloc(n, 0); // leak-note {{allocated here}}
  int ret;

  if (!buf)
    return -ENOMEM;
  ret = setup(dev);
  if (ret)
    return ret; // leak-warning {{'buf' holds memory from kzalloc() that is neither freed nor stored when the function returns here}}
  buf[0] = 1;
  kfree(buf);
  return 0;
}

int freed(struct device *dev, unsigned long n) {
  char *buf = kzalloc(n, 0);
  int ret;

  if (!buf)
    return -ENOMEM;
  ret = setup(dev);
  kfree(buf);
  return ret;
}

int stored(struct priv *p, unsigned long n) {
  char *buf = kzalloc(n, 0);

  if (!buf)
    return -ENOMEM;
  p->buf = buf;
  return setup(p->dev);
}

char *returned(unsigned long n) {
  char *buf = kzalloc(n, 0);

  if (buf)
    buf[0] = 0;
  return buf;
}

void consume(char *buf);

int handed_on(unsigned long n) {
  char *buf = kzalloc(n, 0);

  if (!buf)
    return -ENOMEM;
  consume(buf);
  return 0;
}

// A function whose body is here and that only writes through the pointer.
static int fill(char *buf, int n) {
  buf[0] = n;
  return n;
}

char *kept;
static void keep(char *buf) { kept = buf; }

int through_helper(int n) {
  char *buf = kzalloc(8, 0); // leak-note {{allocated here}}

  if (!buf)
    return -ENOMEM;
  if (fill(buf, n) < 0)
    return -EIO; // leak-warning {{'buf' holds memory from kzalloc()}}
  kfree(buf);
  return 0;
}

int through_keeper(int n) {
  char *buf = kzalloc(8, 0);

  if (!buf)
    return -ENOMEM;
  keep(buf);
  return n;
}
