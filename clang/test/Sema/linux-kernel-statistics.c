// The switch "statistics" says where the bounded analyses stopped short: a
// function without a report is then told from one that was not looked at
// in full.  "all" does not turn it on.
//
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-missing-unwind \
// RUN:   -Wlinux-kernel-experimental -flinux-kernel-experimental=statistics \
// RUN:   -verify=expected,live %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-missing-unwind \
// RUN:   -Wlinux-kernel-experimental \
// RUN:   -flinux-kernel-experimental=statistics,wide-search \
// RUN:   -verify=expected,live %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-missing-unwind \
// RUN:   -Wlinux-kernel-experimental \
// RUN:   -flinux-kernel-experimental=statistics,keep-dead-facts \
// RUN:   -verify=expected,dead %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-missing-unwind \
// RUN:   -Wlinux-kernel-experimental -flinux-kernel-experimental=all \
// RUN:   -verify=off %s

// off-no-diagnostics

// The line for the translation unit is at the start of the file.
// live-warning@1 {{statistics for this file: functions 4, path searches 26, out of steps 0, dropped paths 0, not run 0, checks stopped early 1, tables full 1 (experimental check 'statistics')}}
// dead-warning@1 {{statistics for this file: functions 4, path searches 26, out of steps 0, dropped paths 1, not run 0, checks stopped early 1, tables full 1 (experimental check 'statistics')}}

#define EIO 5

struct device;
struct mutex {
  int owner;
};
struct priv {
  struct device *dev;
  struct mutex lock;
  struct mutex l0;
  struct mutex l1;
  struct mutex l2;
  struct mutex l3;
  struct mutex l4;
  struct mutex l5;
  struct mutex l6;
  struct mutex l7;
  struct mutex l8;
  struct mutex l9;
  struct mutex l10;
  struct mutex l11;
  struct mutex l12;
  struct mutex l13;
  struct mutex l14;
  struct mutex l15;
  struct mutex l16;
  struct mutex l17;
  struct mutex l18;
  struct mutex l19;
  struct mutex l20;
  struct mutex l21;
  struct mutex l22;
  struct mutex l23;
  struct mutex l24;
  struct mutex l25;
};

void mutex_lock(struct mutex *lock);
void mutex_unlock(struct mutex *lock);
int setup(struct device *dev);
void note(int n);

int few(struct priv *p) {
  mutex_lock(&p->lock);
  if (setup(p->dev)) {
    mutex_unlock(&p->lock);
    return -EIO;
  }
  mutex_unlock(&p->lock);
  return 0;
}

// The unwind check follows two dozen acquisitions in one function and then
// leaves the function alone.
int many(struct priv *p) { // expected-warning {{statistics for 'many': path searches 24, out of steps 0, dropped paths 0, not run 0, checks stopped early 1, tables full 0 (experimental check 'statistics')}}
  mutex_lock(&p->l0);
  if (setup(p->dev)) {
    mutex_unlock(&p->l0);
    return -EIO;
  }
  mutex_unlock(&p->l0);
  mutex_lock(&p->l1);
  if (setup(p->dev)) {
    mutex_unlock(&p->l1);
    return -EIO;
  }
  mutex_unlock(&p->l1);
  mutex_lock(&p->l2);
  if (setup(p->dev)) {
    mutex_unlock(&p->l2);
    return -EIO;
  }
  mutex_unlock(&p->l2);
  mutex_lock(&p->l3);
  if (setup(p->dev)) {
    mutex_unlock(&p->l3);
    return -EIO;
  }
  mutex_unlock(&p->l3);
  mutex_lock(&p->l4);
  if (setup(p->dev)) {
    mutex_unlock(&p->l4);
    return -EIO;
  }
  mutex_unlock(&p->l4);
  mutex_lock(&p->l5);
  if (setup(p->dev)) {
    mutex_unlock(&p->l5);
    return -EIO;
  }
  mutex_unlock(&p->l5);
  mutex_lock(&p->l6);
  if (setup(p->dev)) {
    mutex_unlock(&p->l6);
    return -EIO;
  }
  mutex_unlock(&p->l6);
  mutex_lock(&p->l7);
  if (setup(p->dev)) {
    mutex_unlock(&p->l7);
    return -EIO;
  }
  mutex_unlock(&p->l7);
  mutex_lock(&p->l8);
  if (setup(p->dev)) {
    mutex_unlock(&p->l8);
    return -EIO;
  }
  mutex_unlock(&p->l8);
  mutex_lock(&p->l9);
  if (setup(p->dev)) {
    mutex_unlock(&p->l9);
    return -EIO;
  }
  mutex_unlock(&p->l9);
  mutex_lock(&p->l10);
  if (setup(p->dev)) {
    mutex_unlock(&p->l10);
    return -EIO;
  }
  mutex_unlock(&p->l10);
  mutex_lock(&p->l11);
  if (setup(p->dev)) {
    mutex_unlock(&p->l11);
    return -EIO;
  }
  mutex_unlock(&p->l11);
  mutex_lock(&p->l12);
  if (setup(p->dev)) {
    mutex_unlock(&p->l12);
    return -EIO;
  }
  mutex_unlock(&p->l12);
  mutex_lock(&p->l13);
  if (setup(p->dev)) {
    mutex_unlock(&p->l13);
    return -EIO;
  }
  mutex_unlock(&p->l13);
  mutex_lock(&p->l14);
  if (setup(p->dev)) {
    mutex_unlock(&p->l14);
    return -EIO;
  }
  mutex_unlock(&p->l14);
  mutex_lock(&p->l15);
  if (setup(p->dev)) {
    mutex_unlock(&p->l15);
    return -EIO;
  }
  mutex_unlock(&p->l15);
  mutex_lock(&p->l16);
  if (setup(p->dev)) {
    mutex_unlock(&p->l16);
    return -EIO;
  }
  mutex_unlock(&p->l16);
  mutex_lock(&p->l17);
  if (setup(p->dev)) {
    mutex_unlock(&p->l17);
    return -EIO;
  }
  mutex_unlock(&p->l17);
  mutex_lock(&p->l18);
  if (setup(p->dev)) {
    mutex_unlock(&p->l18);
    return -EIO;
  }
  mutex_unlock(&p->l18);
  mutex_lock(&p->l19);
  if (setup(p->dev)) {
    mutex_unlock(&p->l19);
    return -EIO;
  }
  mutex_unlock(&p->l19);
  mutex_lock(&p->l20);
  if (setup(p->dev)) {
    mutex_unlock(&p->l20);
    return -EIO;
  }
  mutex_unlock(&p->l20);
  mutex_lock(&p->l21);
  if (setup(p->dev)) {
    mutex_unlock(&p->l21);
    return -EIO;
  }
  mutex_unlock(&p->l21);
  mutex_lock(&p->l22);
  if (setup(p->dev)) {
    mutex_unlock(&p->l22);
    return -EIO;
  }
  mutex_unlock(&p->l22);
  mutex_lock(&p->l23);
  if (setup(p->dev)) {
    mutex_unlock(&p->l23);
    return -EIO;
  }
  mutex_unlock(&p->l23);
  mutex_lock(&p->l24);
  if (setup(p->dev)) {
    mutex_unlock(&p->l24);
    return -EIO;
  }
  mutex_unlock(&p->l24);
  mutex_lock(&p->l25);
  if (setup(p->dev)) {
    mutex_unlock(&p->l25);
    return -EIO;
  }
  mutex_unlock(&p->l25);
  return 0;
}

// Each flag is tested twice, so the search keeps what the first test found
// out.  Behind the second test nothing mentions the flag any more, and what
// is known about it is dropped: the paths come to the end of the function
// in one state.  With "keep-dead-facts" they come in thirty-two, which is
// more than the search keeps for one block.
int flags(struct priv *p, int a, int b, int c, int d, int e) { // dead-warning {{statistics for 'flags': path searches 1, out of steps 0, dropped paths 1, not run 0, checks stopped early 0, tables full 0 (experimental check 'statistics')}}
  int ret;

  mutex_lock(&p->lock);
  if (a)
    note(1);
  if (a)
    note(2);
  if (b)
    note(3);
  if (b)
    note(4);
  if (c)
    note(5);
  if (c)
    note(6);
  if (d)
    note(7);
  if (d)
    note(8);
  if (e)
    note(9);
  if (e)
    note(10);
  ret = setup(p->dev);
  mutex_unlock(&p->lock);
  return ret;
}

// More conditions than a search has numbers for.  What it cannot number it
// knows nothing about, and the function is one in which a limit was reached
// although no search ran.
#define TEST(n) if (p->lock.owner == (n)) note(n);
#define TEST10(b) TEST(b + 0) TEST(b + 1) TEST(b + 2) TEST(b + 3) TEST(b + 4) \
                  TEST(b + 5) TEST(b + 6) TEST(b + 7) TEST(b + 8) TEST(b + 9)
#define TEST50(b) TEST10(b + 0) TEST10(b + 10) TEST10(b + 20) TEST10(b + 30) \
                  TEST10(b + 40)
void crowded(struct priv *p) { // expected-warning {{statistics for 'crowded': path searches 0, out of steps 0, dropped paths 0, not run 0, checks stopped early 0, tables full 1 (experimental check 'statistics')}}
  TEST50(0) TEST50(50) TEST50(100) TEST50(150) TEST50(200) TEST50(250)
}
