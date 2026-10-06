// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.linux.NodeRef \
// RUN:   -verify %s

#define NULL ((void *)0)
#define ENODEV 19

struct device_node { int id; };
struct resource { int start; };
struct holder { struct device_node *np; };

struct device_node *of_parse_phandle(const struct device_node *np,
                                     const char *name, int index);
struct device_node *of_get_child_by_name(const struct device_node *np,
                                         const char *name);
struct device_node *of_get_next_child(const struct device_node *np,
                                      struct device_node *prev);
struct device_node *of_find_compatible_node(struct device_node *from,
                                            const char *type,
                                            const char *compat);
struct device_node *of_find_node_opts_by_path(const char *path,
                                              const char **opts);
void of_node_put(struct device_node *np);
int of_address_to_resource(struct device_node *np, int index,
                           struct resource *res);
int of_property_read_u32(const struct device_node *np, const char *name,
                         unsigned int *out);
void fwnode_put_node(struct device_node *np);

static inline struct device_node *of_find_node_by_path(const char *path) {
  return of_find_node_opts_by_path(path, NULL);
}

static inline void __free_device_node(void *p) {
  struct device_node *np = *(struct device_node **)p;

  if (np)
    of_node_put(np);
}
#define __free(name) __attribute__((cleanup(__free_##name)))

// The missed of_node_put() on an error path.
int leak_on_error(struct device_node *parent, struct resource *res) {
  struct device_node *np;
  int ret;

  np = of_parse_phandle(parent, "memory-region", 0);
  if (!np)
    return -ENODEV;
  ret = of_address_to_resource(np, 0, res);
  if (ret)
    return ret; // expected-warning {{Device tree node returned by 'of_parse_phandle' is not released with of_node_put()}}
  of_node_put(np);
  return 0;
}

// Never put at all.
int leak_always(struct device_node *parent) {
  struct device_node *child = of_get_child_by_name(parent, "ports");
  unsigned int v = 0;

  if (!child)
    return -ENODEV;
  of_property_read_u32(child, "reg", &v);
  return v; // expected-warning {{Device tree node returned by 'of_get_child_by_name' is not released with of_node_put()}}
}

// Leaving an iteration early keeps the reference of the current child.
int leak_in_loop(struct device_node *parent) {
  struct device_node *child;
  unsigned int v;

  // Once for each of the two calls that can have returned the child.
  for (child = of_get_next_child(parent, NULL); child;
       child = of_get_next_child(parent, child)) {
    if (of_property_read_u32(child, "reg", &v))
      return -ENODEV; // expected-warning 2 {{Device tree node returned by 'of_get_next_child' is not released with of_node_put()}}
  }
  return 0;
}

// Released on every path.
int released(struct device_node *parent, struct resource *res) {
  struct device_node *np = of_parse_phandle(parent, "memory-region", 0);
  int ret;

  if (!np)
    return -ENODEV;
  ret = of_address_to_resource(np, 0, res);
  of_node_put(np);
  return ret;
}

int loop_with_put(struct device_node *parent) {
  struct device_node *child;
  unsigned int v;

  for (child = of_get_next_child(parent, NULL); child;
       child = of_get_next_child(parent, child)) {
    if (of_property_read_u32(child, "reg", &v)) {
      of_node_put(child);
      return -ENODEV;
    }
  }
  return 0;
}

// The reference is handed on.

struct device_node *returned(struct device_node *parent) {
  return of_get_child_by_name(parent, "ports");
}

int stored(struct holder *h, struct device_node *parent) {
  h->np = of_get_child_by_name(parent, "ports");
  return h->np ? 0 : -ENODEV;
}

// The next lookup drops the node it starts from.
int chained(void) {
  struct device_node *np = of_find_compatible_node(NULL, NULL, "a");

  np = of_find_compatible_node(np, NULL, "b");
  of_node_put(np);
  return 0;
}

// Dropped by a function that is named like it.
int put_elsewhere(struct device_node *parent) {
  struct device_node *np = of_get_child_by_name(parent, "ports");

  fwnode_put_node(np);
  return 0;
}

// A cleanup function drops it.
int scoped(struct device_node *parent) {
  struct device_node *np __free(device_node) =
      of_get_child_by_name(parent, "ports");
  unsigned int v = 0;

  if (!np)
    return -ENODEV;
  of_property_read_u32(np, "reg", &v);
  return v;
}

int scoped_through_wrapper(void) {
  struct device_node *np __free(device_node) = of_find_node_by_path("/chosen");

  return np ? 0 : -ENODEV;
}

// Handed over as context data: the action drops the reference later.
int devm_add_action(void *dev, void (*action)(void *), void *data);
void put_node_action(void *data);

int deferred_put(void *dev, struct device_node *parent) {
  struct device_node *np = of_get_child_by_name(parent, "ports");

  if (!np)
    return -ENODEV;
  return devm_add_action(dev, put_node_action, np);
}
