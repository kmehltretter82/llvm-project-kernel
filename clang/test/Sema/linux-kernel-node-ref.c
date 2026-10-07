// A function that looks up a device tree node gets it with a reference,
// which it has to drop on every way out unless it keeps the node.
//
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-experimental \
// RUN:   -I %S/Inputs/linux-kernel \
// RUN:   -flinux-kernel-experimental=node-ref-leak -verify %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -I %S/Inputs/linux-kernel \
// RUN:   -Wall -verify=wall %s

// wall-no-diagnostics

typedef _Bool bool;
#define NULL ((void *)0)
#define EINVAL 22
#define ENODEV 19
#define EPROBE_DEFER 517

struct fwnode_handle {
  int secondary;
};

struct device_node {
  const char *name;
  struct fwnode_handle fwnode;
};

struct device {
  struct device_node *of_node;
  void *driver_data;
};

struct platform_device {
  struct device dev;
};

struct device_node *of_parse_phandle(const struct device_node *np,
                                     const char *name, int index);
struct device_node *of_get_child_by_name(const struct device_node *np,
                                         const char *name);
struct device_node *of_get_parent(const struct device_node *np);
struct device_node *of_get_next_parent(struct device_node *np);
struct device_node *of_node_get(struct device_node *np);
void of_node_put(struct device_node *np);
struct platform_device *of_find_device_by_node(struct device_node *np);
void put_device(struct device *dev);
void *dev_get_drvdata(const struct device *dev);
int of_property_read_u32(const struct device_node *np, const char *name,
                         unsigned int *out);
bool of_device_is_available(const struct device_node *np);
void cleanup_node(struct device_node **np);
#define __free_node __attribute__((cleanup(cleanup_node)))

struct priv {
  struct device_node *np;
  struct device *supplier;
  unsigned int val;
};

// ---------------------------------------------------------------------------
// A way out with the reference.

int on_error_path(struct priv *p, struct device *dev) {
  struct device_node *np;
  int ret;

  np = of_parse_phandle(dev->of_node, "syscon", 0); // expected-note {{the reference is taken here}}
  if (!np)
    return -ENODEV;
  ret = of_property_read_u32(np, "reg", &p->val);
  if (ret)
    return ret; // expected-warning {{the function returns here with the reference to 'np' that of_parse_phandle() took: of_node_put(np) is missing on this path (experimental check 'node-ref-leak')}}
  of_node_put(np);
  return 0;
}

int on_every_path(struct priv *p, struct device *dev) {
  struct device_node *child = of_get_child_by_name(dev->of_node, "ports"); // expected-note {{the reference is taken here}}

  if (!child)
    return -ENODEV;
  return of_property_read_u32(child, "reg", &p->val);
// expected-warning@-1 {{the function returns here with the reference to 'child' that of_get_child_by_name() took, and nothing in the function drops it: of_node_put(child) is missing (experimental check 'node-ref-leak')}}
}

int the_device(struct priv *p, struct device *dev) {
  struct device_node *np = of_parse_phandle(dev->of_node, "supplier", 0);
  struct platform_device *pdev;

  if (!np)
    return -ENODEV;
  pdev = of_find_device_by_node(np); // expected-note {{the reference is taken here}}
  of_node_put(np);
  if (!pdev)
    return -EPROBE_DEFER;
  if (!dev_get_drvdata(&pdev->dev))
    return -EPROBE_DEFER;
// expected-warning@-1 {{the function returns here with the reference to 'pdev' that of_find_device_by_node() took: put_device(&pdev->dev) is missing on this path (experimental check 'node-ref-leak')}}
  put_device(&pdev->dev);
  return 0;
}

struct device_node *of_find_compatible_node(struct device_node *from,
                                            const char *type,
                                            const char *compat);

int looked_up_once(struct priv *p) {
  struct device_node *np;

  np = of_find_compatible_node(NULL, NULL, "vendor,syscon"); // expected-note {{the reference is taken here}}
  if (!np)
    return -ENODEV;
  if (of_property_read_u32(np, "reg", &p->val))
    return -EINVAL;
// expected-warning@-1 {{the function returns here with the reference to 'np' that of_find_compatible_node() took: of_node_put(np) is missing on this path (experimental check 'node-ref-leak')}}
  of_node_put(np);
  return 0;
}

// ---------------------------------------------------------------------------
// Dropped, kept or handed on.

int dropped(struct priv *p, struct device *dev) {
  struct device_node *np;
  int ret;

  np = of_parse_phandle(dev->of_node, "syscon", 0);
  if (!np)
    return -ENODEV;
  ret = of_property_read_u32(np, "reg", &p->val);
  of_node_put(np);
  return ret;
}

int dropped_at_label(struct priv *p, struct device *dev) {
  struct device_node *np;
  int ret;

  np = of_parse_phandle(dev->of_node, "syscon", 0);
  if (!np)
    return -ENODEV;
  ret = of_property_read_u32(np, "reg", &p->val);
  if (ret)
    goto out;
  if (!of_device_is_available(np))
    ret = -ENODEV;
out:
  of_node_put(np);
  return ret;
}

int kept(struct priv *p, struct device *dev) {
  struct device_node *np = of_parse_phandle(dev->of_node, "syscon", 0);

  if (!np)
    return -ENODEV;
  p->np = np;
  return 0;
}

struct device_node *returned_node(struct device *dev) {
  struct device_node *np = of_get_child_by_name(dev->of_node, "ports");

  if (np && !of_device_is_available(np)) {
    of_node_put(np);
    return NULL;
  }
  return np;
}

int kept_device(struct priv *p, struct device *dev) {
  struct device_node *np = of_parse_phandle(dev->of_node, "supplier", 0);
  struct platform_device *pdev;

  if (!np)
    return -ENODEV;
  pdev = of_find_device_by_node(np);
  of_node_put(np);
  if (!pdev)
    return -EPROBE_DEFER;
  p->supplier = &pdev->dev;
  return 0;
}

// The function that goes up drops the node that it is given.
int walked_up(struct device *dev) {
  struct device_node *np = of_node_get(dev->of_node);
  int depth = 0;

  while (np) {
    np = of_get_next_parent(np);
    depth++;
  }
  return depth;
}

int with_cleanup(struct priv *p, struct device *dev) {
  struct device_node *np __free_node =
      of_parse_phandle(dev->of_node, "syscon", 0);

  if (!np)
    return -ENODEV;
  return of_property_read_u32(np, "reg", &p->val);
}

// ---------------------------------------------------------------------------
// One report for a reference, with a note for each other way out that has
// it.

int two_ways_out(struct priv *p, struct device *dev) {
  struct device_node *np = of_parse_phandle(dev->of_node, "syscon", 0); // expected-note {{the reference is taken here}}

  if (!np)
    return -ENODEV;
  if (of_property_read_u32(np, "reg", &p->val))
    return -EINVAL;
// expected-warning@-1 {{the function returns here with the reference to 'np' that of_parse_phandle() took: of_node_put(np) is missing on this path (experimental check 'node-ref-leak')}}
  if (!of_device_is_available(np))
    return -ENODEV; // expected-note {{this way out has the reference as well}}
  of_node_put(np);
  return 0;
}

// ---------------------------------------------------------------------------
// What takes the reference over.

int __devm_add_action_or_reset(struct device *dev, void (*action)(void *),
                               void *data, const char *name);
#define devm_add_action_or_reset(dev, action, data) \
  __devm_add_action_or_reset(dev, action, data, #action)
void put_node_action(void *data);
void put_device_action(void *data);

// An action for when the device goes, which is given the node.
int deferred(struct priv *p, struct device *dev) {
  struct device_node *np = of_get_child_by_name(dev->of_node, "ports");
  int ret;

  if (!np)
    return -ENODEV;
  ret = devm_add_action_or_reset(dev, put_node_action, np);
  if (ret)
    return ret;
  return of_property_read_u32(np, "reg", &p->val);
}

// The action that puts a device is given something of that device.
int deferred_device(struct priv *p, struct device *dev,
                    struct device_node *np) {
  struct platform_device *pdev = of_find_device_by_node(np);
  void *data;
  int ret;

  if (!pdev)
    return -EPROBE_DEFER;
  data = dev_get_drvdata(&pdev->dev);
  if (!data) {
    put_device(&pdev->dev);
    return -EPROBE_DEFER;
  }
  ret = devm_add_action_or_reset(dev, put_device_action, data);
  if (ret)
    return ret;
  p->val = 1;
  return 0;
}

// A function that looks a device up and hands out what belongs to it keeps
// the reference where it succeeds.
void *get_supplier(struct device_node *np) {
  struct platform_device *pdev = of_find_device_by_node(np);
  void *data;

  if (!pdev)
    return NULL;
  data = dev_get_drvdata(&pdev->dev);
  if (!data) {
    put_device(&pdev->dev);
    return NULL;
  }
  return data;
}

// Where it fails it has to drop it.
void *get_supplier_checked(struct device_node *np, struct priv *p) {
  struct platform_device *pdev = of_find_device_by_node(np); // expected-note {{the reference is taken here}}
  void *data;

  if (!pdev)
    return NULL;
  data = dev_get_drvdata(&pdev->dev);
  if (!data) {
    put_device(&pdev->dev);
    return NULL;
  }
  if (!p->val)
    return NULL;
// expected-warning@-1 {{the function returns here with the reference to 'pdev' that of_find_device_by_node() took: put_device(&pdev->dev) is missing on this path (experimental check 'node-ref-leak')}}
  return data;
}

// The reference goes with what is returned.
struct device *companion(struct device_node *np) {
  struct platform_device *pdev = of_find_device_by_node(np);

  return pdev ? &pdev->dev : NULL;
}

struct link {
  const char *name;
  struct device_node *of_node;
};
struct card {
  struct link *links;
  int num;
};

// Stored in a loop: a path around the store is not one that the code has.
int for_the_links(struct card *card, struct device *dev) {
  struct device_node *np = of_parse_phandle(dev->of_node, "codec", 0);
  int i;

  if (!np)
    return -EINVAL;
  for (i = 0; i < card->num; i++) {
    if (card->links[i].name)
      continue;
    card->links[i].of_node = np;
  }
  return 0;
}

// But a way out before the loop is.
int before_the_links(struct card *card, struct device *dev) {
  struct device_node *np = of_parse_phandle(dev->of_node, "codec", 0); // expected-note {{the reference is taken here}}
  int i;

  if (!np)
    return -EINVAL;
  if (!card->num)
    return -EINVAL;
// expected-warning@-1 {{the function returns here with the reference to 'np' that of_parse_phandle() took, and the pointer is not kept here: of_node_put(np) is missing on this path (experimental check 'node-ref-leak')}}
  for (i = 0; i < card->num; i++)
    card->links[i].of_node = np;
  return 0;
}

void component_match_add(struct device *dev, void **match,
                         int (*compare)(struct device *, void *), void *data);
int compare_of(struct device *dev, void *data);

// The node that a component is matched by stays with the match.
int add_component(struct device *dev, void **match) {
  struct device_node *np = of_parse_phandle(dev->of_node, "larb", 0);

  if (!np)
    return -EINVAL;
  component_match_add(dev, match, compare_of, np);
  return 0;
}

#include "driver/other-half.h"

// The other source file of the driver, which may store what it is given.
int for_the_other_half(struct device *dev) {
  struct device_node *np = of_get_child_by_name(dev->of_node, "sensor");

  if (!np)
    return -ENODEV;
  return other_half_init(np);
}

void of_node_put_kunit(void *test, struct device_node *np);

// A put that a subsystem has made its own.
int in_a_test(void *test, struct priv *p) {
  struct device_node *np = of_find_compatible_node(NULL, NULL, "test,node");

  if (!np)
    return -ENODEV;
  of_node_put_kunit(test, np);
  return of_property_read_u32(np, "reg", &p->val);
}

// ---------------------------------------------------------------------------
// No reference to drop.

// The reference is taken under a condition and dropped under the same one.
int guarded(struct device_node *np, const char *name, struct priv *p) {
  struct device_node *found;

  if (name)
    found = of_parse_phandle(np, name, 0);
  else
    found = np;
  if (!found)
    return -ENODEV;
  p->val = of_device_is_available(found);
  if (name)
    of_node_put(found);
  return 0;
}

int get_name(struct device_node *np, int i, const char **name);

// The condition under which it is taken says what a later test finds.
int guarded_by_status(struct device_node *np, struct priv *p) {
  struct device_node *dai = NULL;
  const char *name;
  int ret;

  ret = get_name(np, 0, &name);
  if (ret == 0) {
    dai = of_parse_phandle(np, "sound-dai", 0);
    if (!dai)
      ret = -EINVAL;
  }
  if (ret < 0)
    goto out;
  p->val = of_device_is_available(dai);
  of_node_put(dai);
out:
  return ret;
}

// No node, no parent.
int no_node(struct device_node *np) {
  struct device_node *parent = of_get_parent(np);

  if (!np || !parent)
    return -ENODEV;
  of_node_put(parent);
  return 0;
}

// The variable of a macro.
#define to_handle(node)                                                        \
  ({                                                                           \
    __typeof__(node) __n = (node);                                             \
    __n ? &__n->fwnode : NULL;                                                 \
  })

struct fwnode_handle *handle_of_parent(struct device_node *np) {
  return to_handle(of_get_parent(np));
}

struct fwnode_handle *fwnode_get_parent(const struct fwnode_handle *fwnode);
bool is_port(const struct fwnode_handle *fwnode);

// The nodes of ACPI are not counted.
int acpi_parent_is_port(struct fwnode_handle *fwnode) {
  struct fwnode_handle *parent = fwnode_get_parent(fwnode);

  if (!parent)
    return 0;
  return is_port(parent);
}

int parent_is_port(struct fwnode_handle *fwnode) {
  struct fwnode_handle *parent = fwnode_get_parent(fwnode); // expected-note {{the reference is taken here}}

  if (!parent)
    return 0;
  return is_port(parent);
// expected-warning@-1 {{the function returns here with the reference to 'parent' that fwnode_get_parent() took, and nothing in the function drops it: fwnode_handle_put(parent) is missing (experimental check 'node-ref-leak')}}
}
