// A loop over device tree nodes holds a reference to the node of each pass.
// The iterator drops it when it goes on to the next node, so a pass that
// leaves the function has to drop it itself.
//
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-experimental \
// RUN:   -flinux-kernel-experimental=iterator-ref-leak -verify %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-experimental \
// RUN:   -flinux-kernel-experimental=iterator-ref-leak,iterator-ref-stored \
// RUN:   -verify=expected,stored %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-experimental \
// RUN:   -flinux-kernel-experimental=all -verify %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wall -verify=wall %s

// wall-no-diagnostics

typedef _Bool bool;
#define NULL ((void *)0)
#define EINVAL 22
#define ENODEV 19

struct fwnode_handle {
  int secondary;
};

struct device_node {
  const char *name;
  struct fwnode_handle fwnode;
};

struct device_node *of_get_next_child(const struct device_node *node,
                                      struct device_node *prev);
struct device_node *of_find_compatible_node(struct device_node *from,
                                            const char *type,
                                            const char *compat);
struct device_node *of_node_get(struct device_node *node);
void of_node_put(struct device_node *node);
struct fwnode_handle *fwnode_get_next_child_node(const struct fwnode_handle *fwnode,
                                                 struct fwnode_handle *child);
void fwnode_handle_put(struct fwnode_handle *fwnode);
int of_property_read_u32(const struct device_node *np, const char *name,
                         unsigned int *out);
bool of_device_is_available(const struct device_node *np);
int fwnode_property_read_u32(const struct fwnode_handle *fwnode,
                             const char *name, unsigned int *out);
void cleanup_node(struct device_node **np);

#define for_each_child_of_node(parent, child) \
  for (child = of_get_next_child(parent, NULL); child != NULL; \
       child = of_get_next_child(parent, child))
#define for_each_child_of_node_scoped(parent, child) \
  for (struct device_node *child __attribute__((cleanup(cleanup_node))) = \
           of_get_next_child(parent, NULL); \
       child != NULL; child = of_get_next_child(parent, child))
#define for_each_compatible_node(dn, type, compatible) \
  for (dn = of_find_compatible_node(NULL, type, compatible); dn; \
       dn = of_find_compatible_node(dn, type, compatible))
#define fwnode_for_each_child_node(fwnode, child) \
  for (child = fwnode_get_next_child_node(fwnode, NULL); child; \
       child = fwnode_get_next_child_node(fwnode, child))
#define of_fwnode_handle(node) (&(node)->fwnode)

struct priv {
  struct device_node *np;
  struct fwnode_handle *fw;
  unsigned int val[4];
};

int setup(struct priv *p, unsigned int v);

// ---------------------------------------------------------------------------
// A pass leaves the function with its reference.

int early_return(struct priv *p, struct device_node *parent) {
  struct device_node *child;
  unsigned int v;
  int ret;

  for_each_child_of_node(parent, child) { // expected-note {{the next pass drops the reference here, a pass that leaves the function does not get there}}
    ret = of_property_read_u32(child, "reg", &v);
    if (ret)
      return ret;
// expected-warning@-1 {{the function returns here from inside the loop over nodes, with the reference to 'child' that of_get_next_child() took for this pass: of_node_put(child) is missing on this path (experimental check 'iterator-ref-leak')}}
    p->val[0] = v;
  }
  return 0;
}

int early_return_matching(struct priv *p) {
  struct device_node *np;

  for_each_compatible_node(np, NULL, "vendor,device") { // expected-note {{the next pass drops the reference here, a pass that leaves the function does not get there}}
    if (!of_device_is_available(np))
      continue;
    if (setup(p, 0))
      return -EINVAL;
// expected-warning@-1 {{the function returns here from inside the loop over nodes, with the reference to 'np' that of_find_compatible_node() took for this pass: of_node_put(np) is missing on this path (experimental check 'iterator-ref-leak')}}
  }
  return 0;
}

int while_form(struct priv *p) {
  struct device_node *np = NULL;

  while ((np = of_find_compatible_node(np, NULL, "vendor,device"))) { // expected-note {{the next pass drops the reference here, a pass that leaves the function does not get there}}
    if (setup(p, 1))
      return -ENODEV;
// expected-warning@-1 {{the function returns here from inside the loop over nodes, with the reference to 'np' that of_find_compatible_node() took for this pass: of_node_put(np) is missing on this path (experimental check 'iterator-ref-leak')}}
  }
  return 0;
}

int fwnode_loop(struct priv *p, struct fwnode_handle *parent) {
  struct fwnode_handle *child;
  unsigned int v;

  fwnode_for_each_child_node(parent, child) { // expected-note {{the next pass drops the reference here, a pass that leaves the function does not get there}}
    if (fwnode_property_read_u32(child, "reg", &v))
      return -EINVAL;
// expected-warning@-1 {{the function returns here from inside the loop over nodes, with the reference to 'child' that fwnode_get_next_child_node() took for this pass: fwnode_handle_put(child) is missing on this path (experimental check 'iterator-ref-leak')}}
    p->val[1] = v;
  }
  return 0;
}

// The loop is left with the node, and nothing drops it afterwards.
int found_and_forgotten(struct priv *p, struct device_node *parent) {
  struct device_node *child;
  unsigned int v = 0;

  for_each_child_of_node(parent, child) // expected-note {{the next pass drops the reference here, a pass that leaves the function does not get there}}
    if (!of_property_read_u32(child, "reg", &v))
      break;
  if (!child)
    return -ENODEV;
  return setup(p, v);
// expected-warning@-1 {{the function returns here from inside the loop over nodes, with the reference to 'child' that of_get_next_child() took for this pass: of_node_put(child) is missing on this path (experimental check 'iterator-ref-leak')}}
}

// The handle inside the node is no other reference.
int handle_passed(struct priv *p, struct device_node *parent) {
  struct device_node *child;
  unsigned int v;

  for_each_child_of_node(parent, child) { // expected-note {{the next pass drops the reference here, a pass that leaves the function does not get there}}
    if (fwnode_property_read_u32(of_fwnode_handle(child), "reg", &v))
      return -EINVAL;
// expected-warning@-1 {{the function returns here from inside the loop over nodes, with the reference to 'child' that of_get_next_child() took for this pass: of_node_put(child) is missing on this path (experimental check 'iterator-ref-leak')}}
  }
  return 0;
}

// ---------------------------------------------------------------------------
// The pointer is stored, and the loop drops the only reference to the node.

struct port {
  struct device_node *np;
};

int stored_in_each_pass(struct port *ports, struct device_node *parent) {
  struct device_node *child;
  int n = 0;

  for_each_child_of_node(parent, child) // stored-note {{the reference is dropped here}}
    ports[n++].np = child;
// stored-warning@-1 {{'child' is stored here, but nothing takes a reference for the copy, and the one that the loop holds is dropped when the loop goes on (experimental check 'iterator-ref-stored')}}
  return n;
}

static int add_port(struct port *port, struct device_node *np) {
  port->np = np;
  return 0;
}

int stored_by_helper(struct port *ports, struct device_node *parent) {
  struct device_node *child;
  int n = 0, ret;

  for_each_child_of_node(parent, child) { // stored-note {{the reference is dropped here}}
    ret = add_port(&ports[n++], child);
// stored-warning@-1 {{'child' is given to 'add_port', which keeps it, but nothing takes a reference for the copy, and the one that the loop holds is dropped when the loop goes on (experimental check 'iterator-ref-stored')}}
    if (ret) {
      of_node_put(child);
      return ret;
    }
  }
  return 0;
}

int stored_and_put(struct priv *p, struct device_node *parent) {
  struct device_node *child;

  for_each_child_of_node(parent, child) {
    if (of_device_is_available(child)) {
      p->np = child;
// stored-warning@-1 {{'child' is stored here, but nothing takes a reference for the copy, and the one that the loop holds is dropped afterwards (experimental check 'iterator-ref-stored')}}
      of_node_put(child); // stored-note {{the reference is dropped here}}
      return 0;
    }
  }
  return -ENODEV;
}

// With a reference of its own the copy stands.
int stored_with_reference(struct port *ports, struct device_node *parent) {
  struct device_node *child;
  int n = 0;

  for_each_child_of_node(parent, child)
    ports[n++].np = of_node_get(child);
  return n;
}

// A structure of the function itself is no place that keeps the node.
struct args {
  struct device_node *np;
  int n;
};
int use_args(const struct args *a);

int local_structure(struct device_node *parent) {
  struct device_node *child;
  int n = 0;

  for_each_child_of_node(parent, child) {
    struct args a;

    a.np = child;
    a.n = n;
    n += use_args(&a);
  }
  return n;
}

// Another name for the node of this pass.
int local_name(struct priv *p, struct device_node *parent) {
  struct device_node *child, *np;
  unsigned int v;
  int n = 0;

  for_each_child_of_node(parent, child) {
    np = child;
    if (!of_property_read_u32(np, "reg", &v))
      n++;
  }
  return n;
}

// ---------------------------------------------------------------------------
// The reference is dropped, or kept on purpose.

int put_before_return(struct priv *p, struct device_node *parent) {
  struct device_node *child;
  unsigned int v;
  int ret;

  for_each_child_of_node(parent, child) {
    ret = of_property_read_u32(child, "reg", &v);
    if (ret) {
      of_node_put(child);
      return ret;
    }
  }
  return 0;
}

int put_at_label(struct priv *p, struct device_node *parent) {
  struct device_node *child;
  unsigned int v;
  int ret;

  for_each_child_of_node(parent, child) {
    ret = of_property_read_u32(child, "reg", &v);
    if (ret)
      goto err;
  }
  return 0;
err:
  of_node_put(child);
  return ret;
}

int found_and_put(struct priv *p, struct device_node *parent) {
  struct device_node *child;
  unsigned int v = 0;
  int ret;

  for_each_child_of_node(parent, child)
    if (!of_property_read_u32(child, "reg", &v))
      break;
  if (!child)
    return -ENODEV;
  ret = setup(p, v);
  of_node_put(child);
  return ret;
}

int stored(struct priv *p, struct device_node *parent) {
  struct device_node *child;

  for_each_child_of_node(parent, child) {
    if (of_device_is_available(child)) {
      p->np = child;
      return 0;
    }
  }
  return -ENODEV;
}

int handle_stored(struct priv *p, struct device_node *parent) {
  struct device_node *child;

  for_each_child_of_node(parent, child) {
    if (of_device_is_available(child)) {
      p->fw = of_fwnode_handle(child);
      return 0;
    }
  }
  return -ENODEV;
}

struct device_node *returned(struct device_node *parent) {
  struct device_node *child;

  for_each_child_of_node(parent, child)
    if (of_device_is_available(child))
      return child;
  return NULL;
}

int another_reference(struct priv *p, struct device_node *parent) {
  struct device_node *child;

  for_each_child_of_node(parent, child) {
    if (of_device_is_available(child)) {
      p->np = of_node_get(child);
      of_node_put(child);
      return 0;
    }
  }
  return -ENODEV;
}

// The device keeps the node, with the reference that the loop took.
struct device;
void device_set_node(struct device *dev, struct fwnode_handle *fwnode);
int dev_err_probe(const struct device *dev, int err, const char *fmt, ...);

int given_to_device(struct device *dev, struct fwnode_handle *parent) {
  struct fwnode_handle *child;
  unsigned int v;

  fwnode_for_each_child_node(parent, child)
    if (!fwnode_property_read_u32(child, "reg", &v))
      break;
  device_set_node(dev, child);
  return 0;
}

static void remember(struct priv *p, struct device_node *np) {
  p->np = np;
}

int given_to_helper(struct priv *p, struct device_node *parent) {
  struct device_node *child;

  for_each_child_of_node(parent, child) {
    if (of_device_is_available(child)) {
      remember(p, child);
      return 0;
    }
  }
  return -ENODEV;
}

// The error that dev_err_probe() returns is the one that it was given.
int error_from_message(struct device *dev, struct priv *p,
                       struct device_node *parent) {
  struct device_node *child;
  unsigned int v;
  int ret = 0;

  for_each_child_of_node(parent, child) {
    if (of_property_read_u32(child, "reg", &v)) {
      ret = dev_err_probe(dev, -EINVAL, "no reg\n");
      break;
    }
  }
  if (ret) {
    of_node_put(child);
    return ret;
  }
  return setup(p, 0);
}

int scoped(struct priv *p, struct device_node *parent) {
  unsigned int v;
  int ret;

  for_each_child_of_node_scoped(parent, child) {
    ret = of_property_read_u32(child, "reg", &v);
    if (ret)
      return ret;
  }
  return 0;
}

int every_pass_goes_on(struct priv *p, struct device_node *parent) {
  struct device_node *child;
  unsigned int v;
  int n = 0;

  for_each_child_of_node(parent, child) {
    if (of_property_read_u32(child, "reg", &v))
      continue;
    n++;
  }
  return n;
}
